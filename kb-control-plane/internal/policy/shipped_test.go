package policy

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

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

func TestKnownDestinations(t *testing.T) {
	write := func(body string) *Engine {
		f := filepath.Join(t.TempDir(), "p.yaml")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		e, err := New(f)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := write("known_destinations: [\"10.1.2.3\", \"192.168.50.0/24\"]\n")
	for ip, want := range map[string]bool{"10.1.2.3": true, "10.1.2.4": false, "192.168.50.200": true, "8.8.8.8": false} {
		if got := e.IsKnownDestination(net.ParseIP(ip)); got != want {
			t.Errorf("%s: got %v want %v", ip, got, want)
		}
	}
	if e.IsKnownDestination(net.ParseIP("::1")) {
		t.Error("IPv6 must not match")
	}
	// A bad entry rejects the whole list; a /0 would mark everything known.
	for _, body := range []string{
		"known_destinations: [\"10.1.2.3\", \"not-an-ip\"]\n",
		"known_destinations: [\"0.0.0.0/0\"]\n",
		"known_destinations: [\"::1\"]\n",
		"known_destinations: [\"\"]\n",
	} {
		if write(body).IsKnownDestination(net.ParseIP("10.1.2.3")) {
			t.Errorf("list should be rejected as a whole: %s", body)
		}
	}
	for _, p := range []string{"../../config/policy.yaml", "../../../config/policy.yaml"} {
		pe, err := New(p)
		if err != nil {
			t.Fatal(err)
		}
		if pe.IsKnownDestination(net.ParseIP("10.1.2.3")) {
			t.Errorf("%s: shipped default must list no known destinations", p)
		}
	}
}
