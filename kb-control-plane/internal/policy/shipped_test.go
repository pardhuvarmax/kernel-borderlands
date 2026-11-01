package policy

import "testing"

// The policy files shipped in the repo must parse with the real loader, and
// must not carry lab-only paths or auto-kill defaults for databases.
func TestShippedPolicyFilesLoad(t *testing.T) {
	for _, p := range []string{"../../config/policy.yaml", "../../../config/policy.yaml"} {
		e, err := New(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got := e.SensitivePaths(); len(got) != 0 {
			t.Errorf("%s: default sensitive_paths = %v, want empty", p, got)
		}
		if e.AutoTerminate("postgres") {
			t.Errorf("%s: postgres auto_terminate must default to false", p)
		}
	}
}
