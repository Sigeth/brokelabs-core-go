package kubeexec

import (
	"os/exec"
	"slices"
	"testing"
)

func TestAsUser(t *testing.T) {
	cmd := []string{"/bin/sh", "-c", "echo 'it''s' \"$HOME\""}
	if got := AsUser("root", cmd); !slices.Equal(got, cmd) {
		t.Errorf("root: %q", got)
	}
	if got := AsUser("", cmd); !slices.Equal(got, cmd) {
		t.Errorf("empty: %q", got)
	}
	got := AsUser("student", cmd)
	if !slices.Equal(got[:5], []string{"su", "-s", "/bin/sh", "student", "-c"}) {
		t.Fatalf("student: %q", got)
	}
	// The quoted command must give back the original words.
	out, err := exec.Command("/bin/sh", "-c", "printf '%s\\n' "+got[5][len("'/bin/sh' "):]).Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := "-c\necho 'it''s' \"$HOME\"\n"; string(out) != want {
		t.Errorf("words = %q, want %q", out, want)
	}
}
