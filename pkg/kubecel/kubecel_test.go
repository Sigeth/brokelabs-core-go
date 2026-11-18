package kubecel

import (
	"strings"
	"testing"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
)

func pod(name string, automount any, memory string) Object {
	spec := map[string]any{"containers": []any{map[string]any{
		"name":      "c",
		"resources": map[string]any{"limits": map[string]any{"memory": memory}},
	}}}
	if automount != nil {
		spec["automountServiceAccountToken"] = automount
	}
	return Object{Name: "payments/" + name, Value: map[string]any{"metadata": map[string]any{"name": name}, "spec": spec}}
}

func check(all, any, none string) *v1alpha1.KubeCELCheck {
	return &v1alpha1.KubeCELCheck{Resource: v1alpha1.ResourceSelector{APIVersion: "v1", Kind: "Pod"}, All: all, Any: any, None: none}
}

func TestEvaluate(t *testing.T) {
	good, bad, unset := pod("good", false, "256Mi"), pod("bad", true, "2Gi"), pod("unset", nil, "256Mi")
	tests := []struct {
		name    string
		check   *v1alpha1.KubeCELCheck
		objects []Object
		pass    bool
		message string
	}{
		{"all pass", check("object.spec.automountServiceAccountToken == false", "", ""), []Object{good}, true, "all 1 Pod"},
		{"all fail", check("object.spec.automountServiceAccountToken == false", "", ""), []Object{good, bad}, false, "payments/bad"},
		{"all needs objects", check("true", "", ""), nil, false, "no Pod found"},
		// A missing field is an evaluation error: it fails closed.
		{"all missing field", check("object.spec.automountServiceAccountToken == false", "", ""), []Object{unset}, false, "payments/unset"},
		{"optional field", check("object.spec.?automountServiceAccountToken.orValue(true) == false", "", ""), []Object{good, unset}, false, "payments/unset"},
		{"kubernetes quantity", check(`object.spec.containers.all(c, quantity(c.resources.limits.memory).isLessThan(quantity("1Gi")))`, "", ""), []Object{good}, true, ""},
		{"any", check("", "object.metadata.name == 'good'", ""), []Object{bad, good}, true, "payments/good"},
		{"any none match", check("", "object.metadata.name == 'x'", ""), []Object{bad}, false, "none of the 1"},
		{"none pass", check("", "", "object.spec.automountServiceAccountToken == true"), []Object{good}, true, ""},
		{"none fail", check("", "", "object.spec.automountServiceAccountToken == true"), []Object{good, bad}, false, "payments/bad"},
		{"none with errors fails", check("", "", "object.spec.automountServiceAccountToken == true"), []Object{unset}, false, "payments/unset"},
		{"none of nothing", check("", "", "true"), nil, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pass, msg, err := Evaluate(tt.check, tt.objects)
			if err != nil {
				t.Fatal(err)
			}
			if pass != tt.pass || !strings.Contains(msg, tt.message) {
				t.Fatalf("Evaluate = %v, %q; want %v, containing %q", pass, msg, tt.pass, tt.message)
			}
		})
	}
}

func TestCompileRejects(t *testing.T) {
	for _, expr := range []string{"object.", "1 + 1", "'text'"} {
		if _, err := Compile(expr); err == nil {
			t.Errorf("%q compiled", expr)
		}
	}
}
