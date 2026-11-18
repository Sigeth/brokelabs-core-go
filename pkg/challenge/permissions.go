package challenge

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
)

// Default resources of a machine that declares none.
var (
	DefaultMachineCPU    = resource.MustParse("250m")
	DefaultMachineMemory = resource.MustParse("256Mi")
	// The resources of a vcluster machine are the budget of the whole
	// virtual cluster: its control plane and the student's workloads.
	DefaultVClusterCPU    = resource.MustParse("2")
	DefaultVClusterMemory = resource.MustParse("2Gi")
	MinVClusterCPU        = resource.MustParse("1")
	MinVClusterMemory     = resource.MustParse("1Gi")
)

// MachineResources returns the CPU and memory a machine requests.
func MachineResources(m v1alpha1.Machine) (cpu, memory resource.Quantity) {
	switch {
	case m.Resources != nil:
		return m.Resources.CPU, m.Resources.Memory
	case m.Runtime == v1alpha1.RuntimeVCluster:
		return DefaultVClusterCPU, DefaultVClusterMemory
	}
	return DefaultMachineCPU, DefaultMachineMemory
}

// Permissions derives what a package needs from the cluster (D41): its
// runtimes, the resources of its machines, its egress, the kinds of its
// extraManifests (read from files) and its custom checker.
func Permissions(p *v1alpha1.ChallengePackage, files map[string][]byte) (*v1alpha1.RequiredPermissions, error) {
	perms := &v1alpha1.RequiredPermissions{Egress: v1alpha1.EgressNone}
	cpu, memory := resource.Quantity{}, resource.Quantity{}
	for _, m := range p.Spec.Machines {
		if !slices.Contains(perms.Runtimes, m.Runtime) {
			perms.Runtimes = append(perms.Runtimes, m.Runtime)
		}
		c, mem := MachineResources(m)
		cpu.Add(c)
		memory.Add(mem)
	}
	slices.Sort(perms.Runtimes)
	perms.CPU, perms.Memory = canonical(cpu), canonical(memory)
	if s := p.Spec.Permissions; s != nil {
		if s.Egress != "" {
			perms.Egress = s.Egress
		}
		perms.EgressAllowlist = slices.Clone(s.EgressAllowlist)
	}
	for _, name := range p.Spec.ExtraManifests {
		kinds, err := manifestKinds(name, files)
		if err != nil {
			return nil, err
		}
		for _, k := range kinds {
			if !slices.Contains(perms.ExtraManifestKinds, k) {
				perms.ExtraManifestKinds = append(perms.ExtraManifestKinds, k)
			}
		}
	}
	slices.Sort(perms.ExtraManifestKinds)
	if v := p.Spec.Validation; v != nil {
		perms.CheckerImage = v.CheckerImage
	}
	return perms, nil
}

// canonical rewrites a quantity in its canonical form, so equal sums compare
// and print the same whatever their parts.
func canonical(q resource.Quantity) resource.Quantity {
	return resource.MustParse(q.String())
}

// manifestKinds returns the kinds of the objects in an extra manifest (a
// file, or every file of a directory, of YAML or JSON documents).
func manifestKinds(root string, files map[string][]byte) ([]string, error) {
	var kinds []string
	found := false
	for name, data := range files {
		if name != root && !strings.HasPrefix(name, root+"/") {
			continue
		}
		found = true
		dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for {
			var obj struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
			}
			err := dec.Decode(&obj)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if obj.APIVersion == "" && obj.Kind == "" {
				continue // empty document
			}
			gv, err := schema.ParseGroupVersion(obj.APIVersion)
			if err != nil || obj.Kind == "" {
				return nil, fmt.Errorf("%s: every object needs an apiVersion and a kind", name)
			}
			if strings.HasSuffix(obj.Kind, "List") {
				return nil, fmt.Errorf("%s: %s: list objects are not supported, write one document per object", name, obj.Kind)
			}
			kinds = append(kinds, KindName(gv.Group, obj.Kind))
		}
	}
	if !found {
		return nil, fmt.Errorf("%s: not in the package", root)
	}
	return kinds, nil
}

// KindName names a kind as in RequiredPermissions: "Kind" for the core
// group, "Kind.group" otherwise.
func KindName(group, kind string) string {
	if group == "" {
		return kind
	}
	return kind + "." + group
}

// PolicyViolations lists what perms needs and policy refuses: runtimes,
// egress, instance resources and extra manifest kinds. Whether the cluster
// supports a runtime is a separate question (the operator's).
func PolicyViolations(perms *v1alpha1.RequiredPermissions, policy v1alpha1.PlatformConfigSpec) []string {
	var v []string
	for _, r := range perms.Runtimes {
		if len(policy.AllowedRuntimes) > 0 && !slices.Contains(policy.AllowedRuntimes, r) {
			v = append(v, fmt.Sprintf("the %s runtime is not allowed", r))
		}
	}
	allowed := policy.AllowedEgress
	if allowed == "" {
		allowed = v1alpha1.EgressNone
	}
	if egressRank(perms.Egress) > egressRank(allowed) {
		v = append(v, fmt.Sprintf("%s egress is not allowed (at most %s)", perms.Egress, allowed))
	}
	if max := policy.MaxInstanceResources; max != nil {
		if max.CPU != nil && perms.CPU.Cmp(*max.CPU) > 0 {
			v = append(v, fmt.Sprintf("an instance requests %s CPU, more than the %s allowed", perms.CPU.String(), max.CPU.String()))
		}
		if max.Memory != nil && perms.Memory.Cmp(*max.Memory) > 0 {
			v = append(v, fmt.Sprintf("an instance requests %s of memory, more than the %s allowed", perms.Memory.String(), max.Memory.String()))
		}
	}
	kinds := policy.AllowedExtraManifestKinds
	if len(kinds) == 0 {
		kinds = v1alpha1.DefaultExtraManifestKinds
	}
	if !slices.Contains(kinds, v1alpha1.AllKinds) {
		for _, k := range perms.ExtraManifestKinds {
			if !slices.Contains(kinds, k) {
				v = append(v, fmt.Sprintf("extra manifests of kind %s are not allowed", k))
			}
		}
	}
	return v
}

// egressRank orders egress modes from the most closed.
func egressRank(m v1alpha1.EgressMode) int {
	switch m {
	case v1alpha1.EgressInternet:
		return 2
	case v1alpha1.EgressAllowlist:
		return 1
	default:
		return 0
	}
}

// SamePermissions reports whether two permission sets are equal.
func SamePermissions(a, b *v1alpha1.RequiredPermissions) bool {
	return equality.Semantic.DeepEqual(a, b)
}
