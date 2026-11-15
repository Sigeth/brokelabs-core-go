package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
)

// RequiredPermissions are what a package needs from the cluster. They are
// derived from the package itself (D41), never declared, except egress, so an
// author cannot under-declare them. Admins see them before installing, and
// PlatformConfig policy can refuse them.
type RequiredPermissions struct {
	// Runtimes used by the machines, sorted.
	Runtimes []Runtime `json:"runtimes"`
	// CPU requested by the machines of one instance.
	CPU resource.Quantity `json:"cpu"`
	// Memory requested by the machines of one instance.
	Memory resource.Quantity `json:"memory"`
	// Egress is the outbound network access of an instance.
	Egress EgressMode `json:"egress"`
	// EgressAllowlist lists the host names reachable when egress is "allowlist".
	// +optional
	EgressAllowlist []string `json:"egressAllowlist,omitempty"`
	// ExtraManifestKinds are the kinds created in the instance namespace by
	// extraManifests, as "Kind" (core group) or "Kind.group", sorted.
	// +optional
	ExtraManifestKinds []string `json:"extraManifestKinds,omitempty"`
	// CheckerImage is the custom checker, which runs with access to the
	// machines of the instance.
	// +optional
	CheckerImage string `json:"checkerImage,omitempty"`
}

// InstanceResources bounds the resources of one instance.
type InstanceResources struct {
	// CPU requested by the machines of one instance.
	// +optional
	CPU *resource.Quantity `json:"cpu,omitempty"`
	// Memory requested by the machines of one instance.
	// +optional
	Memory *resource.Quantity `json:"memory,omitempty"`
}

// AllKinds in PlatformConfigSpec.AllowedExtraManifestKinds allows every
// namespaced kind.
const AllKinds = "*"

// DefaultExtraManifestKinds are the kinds extraManifests may create when
// PlatformConfigSpec.AllowedExtraManifestKinds is empty: workloads and their
// configuration, nothing that changes permissions (RBAC) or the network
// (NetworkPolicy).
var DefaultExtraManifestKinds = []string{
	"ConfigMap", "Secret", "Service", "ServiceAccount",
	"Deployment.apps", "StatefulSet.apps", "DaemonSet.apps", "Job.batch", "CronJob.batch",
}
