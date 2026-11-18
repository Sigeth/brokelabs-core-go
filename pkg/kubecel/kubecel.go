// Package kubecel evaluates kubeCEL checks: CEL expressions over Kubernetes
// objects, with the same language as Kubernetes' own CEL (ValidatingAdmissionPolicy,
// CRD validation rules): its base environment and libraries (lists, regex,
// URLs, quantities, IPs, CIDRs, formats, semver, optional fields). The
// expression sees the object as `object`, a JSON map.
//
// Challenge validation compiles the expressions with Compile; the checker
// evaluates them with Evaluate, so both accept exactly the same expressions.
package kubecel

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"k8s.io/apiserver/pkg/cel/environment"

	"github.com/Sigeth/brokelabs-core-go/api/v1alpha1"
)

// Variable is the name of the object in expressions.
const Variable = "object"

var (
	envOnce sync.Once
	env     *cel.Env
	envErr  error
)

// Env returns the CEL environment of kubeCEL expressions.
func Env() (*cel.Env, error) {
	envOnce.Do(func() {
		version := environment.DefaultCompatibilityVersion()
		set, err := environment.MustBaseEnvSet(version).Extend(environment.VersionedOptions{
			IntroducedVersion: version,
			EnvOptions:        []cel.EnvOption{cel.Variable(Variable, cel.DynType)},
		})
		if err != nil {
			envErr = err
			return
		}
		env, envErr = set.Env(environment.StoredExpressions)
	})
	return env, envErr
}

// Compile compiles an expression that must evaluate to a bool.
func Compile(expr string) (cel.Program, error) {
	e, err := Env()
	if err != nil {
		return nil, err
	}
	ast, issues := e.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	if t := ast.OutputType(); t != cel.BoolType && t != cel.DynType {
		return nil, fmt.Errorf("must evaluate to a bool, not %s", t)
	}
	return e.Program(ast)
}

// Mode is how the expression must hold over the selected objects.
type Mode string

const (
	// All: true for every object, and at least one object is selected.
	All Mode = "all"
	// Any: true for at least one object.
	Any Mode = "any"
	// None: false for every object (passes when nothing is selected).
	None Mode = "none"
)

// Expression returns the mode and expression a check sets.
func Expression(c *v1alpha1.KubeCELCheck) (Mode, string) {
	switch {
	case c.All != "":
		return All, c.All
	case c.Any != "":
		return Any, c.Any
	}
	return None, c.None
}

// Object is a selected object: its JSON map and a name for messages
// ("namespace/name").
type Object struct {
	Name  string
	Value map[string]any
}

// maxNamed bounds the objects named in a failure message.
const maxNamed = 3

// Evaluate checks the expression of a kubeCEL check against the selected
// objects, of the given kind (for messages). It returns whether the check
// passes and a message for the student. An object on which the expression
// cannot be evaluated (a missing field, a wrong type) counts against the
// check: it fails closed.
func Evaluate(c *v1alpha1.KubeCELCheck, objects []Object) (bool, string, error) {
	mode, expr := Expression(c)
	prg, err := Compile(expr)
	if err != nil {
		return false, "", fmt.Errorf("%s: %w", mode, err)
	}
	kind := c.Resource.Kind
	// Each object is true, false, or broken (the expression cannot be
	// evaluated on it), which counts against the check in every mode.
	var isTrue, notTrue, notFalse []string
	for _, obj := range objects {
		out, _, err := prg.Eval(map[string]any{Variable: obj.Value})
		var b, ok bool
		if err == nil {
			b, ok = out.Value().(bool)
		}
		switch {
		case ok && b:
			isTrue = append(isTrue, obj.Name)
			notFalse = append(notFalse, obj.Name)
		case ok:
			notTrue = append(notTrue, obj.Name)
		default:
			notTrue = append(notTrue, obj.Name)
			notFalse = append(notFalse, obj.Name)
		}
	}
	switch mode {
	case All:
		switch {
		case len(objects) == 0:
			return false, fmt.Sprintf("no %s found", kind), nil
		case len(notTrue) > 0:
			return false, fmt.Sprintf("%d of %d %s objects do not comply: %s", len(notTrue), len(objects), kind, names(notTrue)), nil
		}
		return true, fmt.Sprintf("all %d %s objects comply", len(objects), kind), nil
	case Any:
		if len(isTrue) == 0 {
			return false, fmt.Sprintf("none of the %d %s objects complies", len(objects), kind), nil
		}
		return true, fmt.Sprintf("%s complies", names(isTrue)), nil
	default:
		if len(notFalse) > 0 {
			return false, fmt.Sprintf("%d of %d %s objects do not comply: %s", len(notFalse), len(objects), kind, names(notFalse)), nil
		}
		return true, fmt.Sprintf("none of the %d %s objects is at fault", len(objects), kind), nil
	}
}

func names(list []string) string {
	sorted := append([]string(nil), list...)
	sort.Strings(sorted)
	if len(sorted) > maxNamed {
		return strings.Join(sorted[:maxNamed], ", ") + fmt.Sprintf(" and %d more", len(sorted)-maxNamed)
	}
	return strings.Join(sorted, ", ")
}
