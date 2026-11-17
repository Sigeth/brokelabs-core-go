package challenge

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
)

func permissionsPackage() *v1alpha1.ChallengePackage {
	one := resource.MustParse("1")
	gi := resource.MustParse("1Gi")
	return &v1alpha1.ChallengePackage{Spec: v1alpha1.ChallengePackageSpec{
		Machines: []v1alpha1.Machine{
			{Name: "server", Runtime: v1alpha1.RuntimeVM, Resources: &v1alpha1.MachineResources{CPU: one, Memory: gi}},
			{Name: "box", Runtime: v1alpha1.RuntimePod}, // default resources
			{Name: "box2", Runtime: v1alpha1.RuntimePod},
		},
		Permissions:    &v1alpha1.Permissions{Egress: v1alpha1.EgressInternet},
		ExtraManifests: []string{"setup/manifests", "setup/extra.json"},
		Validation:     &v1alpha1.Validation{CheckerImage: "ghcr.io/x/checker@sha256:0"},
	}}
}

var manifestFiles = map[string][]byte{
	"setup/manifests/app.yaml": []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: a}\n---\n" +
		"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: b}\n---\n"),
	"setup/manifests/nested/cm.yaml": []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"),
	"setup/extra.json":               []byte(`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"r"}}`),
}

func TestPermissions(t *testing.T) {
	perms, err := Permissions(permissionsPackage(), manifestFiles)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(runtimeNames(perms.Runtimes), ",") != "pod,vm" {
		t.Errorf("runtimes = %v", perms.Runtimes)
	}
	if perms.CPU.String() != "1500m" || perms.Memory.String() != "1536Mi" {
		t.Errorf("resources = %s CPU, %s", perms.CPU.String(), perms.Memory.String())
	}
	if got := strings.Join(perms.ExtraManifestKinds, ","); got != "ConfigMap,Deployment.apps,Role.rbac.authorization.k8s.io" {
		t.Errorf("kinds = %s", got)
	}
	if perms.Egress != v1alpha1.EgressInternet || perms.CheckerImage == "" {
		t.Errorf("permissions = %+v", perms)
	}

	again, _ := Permissions(permissionsPackage(), manifestFiles)
	if !SamePermissions(perms, again) {
		t.Error("the same package must give the same permissions")
	}
	again.ExtraManifestKinds = again.ExtraManifestKinds[1:]
	if SamePermissions(perms, again) {
		t.Error("different permissions must differ")
	}

	minimal, err := Permissions(&v1alpha1.ChallengePackage{Spec: v1alpha1.ChallengePackageSpec{
		Machines: []v1alpha1.Machine{{Name: "box", Runtime: v1alpha1.RuntimePod}}}}, nil)
	if err != nil || minimal.Egress != v1alpha1.EgressNone || minimal.CPU.String() != "250m" {
		t.Fatalf("minimal = %+v, %v", minimal, err)
	}
}

func runtimeNames(rs []v1alpha1.Runtime) []string {
	var names []string
	for _, r := range rs {
		names = append(names, string(r))
	}
	return names
}

func TestPermissionsRefuseBadManifests(t *testing.T) {
	for name, content := range map[string]string{
		"no kind": "apiVersion: v1\nmetadata: {name: x}\n",
		"list":    "apiVersion: v1\nkind: ConfigMapList\nitems: []\n",
		"broken":  "apiVersion: v1\nkind: [\n",
	} {
		p := permissionsPackage()
		p.Spec.ExtraManifests = []string{"m.yaml"}
		if _, err := Permissions(p, map[string][]byte{"m.yaml": []byte(content)}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	p := permissionsPackage()
	p.Spec.ExtraManifests = []string{"missing.yaml"}
	if _, err := Permissions(p, nil); err == nil || !strings.Contains(err.Error(), "not in the package") {
		t.Errorf("error = %v", err)
	}
}

func TestPolicyViolations(t *testing.T) {
	perms, err := Permissions(permissionsPackage(), manifestFiles)
	if err != nil {
		t.Fatal(err)
	}
	cpu, memory := resource.MustParse("1"), resource.MustParse("2Gi")

	open := v1alpha1.PlatformConfigSpec{AllowedEgress: v1alpha1.EgressInternet, AllowedExtraManifestKinds: []string{v1alpha1.AllKinds}}
	if v := PolicyViolations(perms, open); len(v) != 0 {
		t.Fatalf("an open policy refuses %v", v)
	}

	strict := v1alpha1.PlatformConfigSpec{
		AllowedRuntimes:      []v1alpha1.Runtime{v1alpha1.RuntimePod},
		MaxInstanceResources: &v1alpha1.InstanceResources{CPU: &cpu, Memory: &memory},
	}
	got := strings.Join(PolicyViolations(perms, strict), "; ")
	for _, want := range []string{
		"the vm runtime is not allowed",
		"internet egress is not allowed (at most none)",
		"1500m CPU, more than the 1 allowed",
		"kind Role.rbac.authorization.k8s.io are not allowed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("violations %q miss %q", got, want)
		}
	}
	// Memory fits; ConfigMap and Deployment are default kinds.
	for _, notWant := range []string{"memory", "ConfigMap", "Deployment"} {
		if strings.Contains(got, notWant) {
			t.Errorf("violations %q must not mention %s", got, notWant)
		}
	}
}
