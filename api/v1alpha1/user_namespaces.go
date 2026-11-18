package v1alpha1

import "github.com/Sigeth/brokelabs-core-go/pkg/project"

// User namespaces (D50). Instance namespaces with a userns or vcluster machine
// enforce the "baseline" Pod Security Standard instead of "restricted", and
// carry LabelUserNamespaces. The platform chart installs a
// MutatingAdmissionPolicy that sets hostUsers: false on every pod created in
// those namespaces, and a ValidatingAdmissionPolicy that rejects any pod
// without it. Both policies and their bindings are named UserNamespacesPolicy;
// the operator only offers the runtimes that need them when all four exist.
const (
	// LabelUserNamespaces is set to "true" on namespaces whose pods must run
	// in user namespaces.
	LabelUserNamespaces = project.LabelPrefix + "user-namespaces"
	// UserNamespacesPolicy names the admission policies and their bindings.
	UserNamespacesPolicy = project.Name + "-user-namespaces"
	// NetworkPoliciesPolicy names the ValidatingAdmissionPolicy (and its
	// binding) that lets only the operator write NetworkPolicies reaching
	// outside a labelled namespace (D51). vcluster machines need it.
	NetworkPoliciesPolicy = project.Name + "-instance-network-policies"
)

// NeedsUserNamespaces reports whether a runtime runs pods as root, so that its
// instance namespace must enforce user namespaces.
func (r Runtime) NeedsUserNamespaces() bool {
	return r == RuntimeUserns || r == RuntimeVCluster
}
