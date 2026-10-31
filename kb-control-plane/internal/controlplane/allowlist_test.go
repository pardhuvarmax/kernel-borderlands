package controlplane

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/policy"
	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
)

func TestTrustedExecutable(t *testing.T) {
	for p, want := range map[string]bool{
		"/usr/bin/sudo":            true,
		"/usr/lib/systemd/systemd": true,
		"/usr/sbin/sshd":           true,
		"/tmp/systemd":             false, // the malware-renames-itself case
		"/home/u/.cache/systemd":   false,
		"/dev/shm/sshd":            false,
		"/usr/bin/sudo (deleted)":  false, // binary replaced/removed after start
		"":                         false,
		"/usr/binx/evil":           false, // prefix must be a real directory boundary
	} {
		if got := trustedExecutable(p); got != want {
			t.Errorf("trustedExecutable(%q) = %v, want %v", p, got, want)
		}
	}
}

func withAllowlist(t *testing.T, cp *ControlPlane, comm string, exe string, exeErr error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "allowlist.yaml")
	os.WriteFile(p, []byte("allow:\n  - comm: "+comm+"\n    reason: test entry\n"), 0o644)
	a, err := policy.LoadAllowlist(p)
	if err != nil {
		t.Fatal(err)
	}
	cp.SetAllowlist(p, a)
	prev, prevOwn := resolveExe, exeOwnedByRoot
	resolveExe = func(uint32) (string, error) { return exe, exeErr }
	exeOwnedByRoot = func(string) bool { return true }
	t.Cleanup(func() { resolveExe, exeOwnedByRoot = prev, prevOwn })
}

// enterBorderlands (controlplane_test.go) uses comm "evil".
func TestAllowlisted_TrustedBinarySuppressesAutoContainmentButIsAuditedAndTagged(t *testing.T) {
	cp := newTestControlPlane(t)
	withAllowlist(t, cp, "evil", "/usr/bin/evil", nil)
	ch := make(chan *pb.KBEvent, 4)
	cp.subMu.Lock()
	cp.eventSubs = append(cp.eventSubs, ch)
	cp.subMu.Unlock()
	cp, got := enterBorderlandsWith(t, cp)
	select {
	case <-got:
		t.Fatal("an allowlisted, verified binary must not be auto-contained")
	case <-time.After(500 * time.Millisecond):
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !hasAction(auditActions(t, cp), "ALLOWLIST_EXEMPT_CGROUP_THROTTLE") {
		time.Sleep(20 * time.Millisecond)
	}
	a := auditActions(t, cp)
	if !hasAction(a, "ALLOWLIST_EXEMPT_CGROUP_THROTTLE") || hasAction(a, "CGROUP_THROTTLE") {
		t.Errorf("want ALLOWLIST_EXEMPT_CGROUP_THROTTLE and no CGROUP_THROTTLE, got %v", a)
	}
	if !hasAction(a, "ZONE_SUSPICIOUS_TO_BORDERLANDS") {
		t.Errorf("the zone change itself must still be audited, got %v", a)
	}
	var tagged bool
	for len(ch) > 0 {
		if e := <-ch; e.EventType == "zone_transition" && e.Metadata["allowlisted"] == "test entry" && e.Metadata["to_zone"] == "BORDERLANDS" {
			tagged = true
		}
	}
	if !tagged {
		t.Error("the zone_transition event must keep the TRUE zone and carry allowlisted=<reason>")
	}
}

func TestAllowlisted_SpoofedCommFromUntrustedPathIsNotExempt(t *testing.T) {
	cp := newTestControlPlane(t)
	withAllowlist(t, cp, "evil", "/tmp/evil", nil) // comm matches, binary is in /tmp
	cp, got := enterBorderlandsWith(t, cp)
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("a process spoofing an allowlisted comm from /tmp must still be contained")
	}
}

func TestAllowlisted_ExitedOrUnresolvableProcessFailsClosed(t *testing.T) {
	cp := newTestControlPlane(t)
	withAllowlist(t, cp, "evil", "", errors.New("readlink: no such file"))
	cp, got := enterBorderlandsWith(t, cp)
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("when the executable cannot be verified the process must not be exempt")
	}
}

// The hole a trusted-DIRECTORY check alone leaves: /usr/bin/python3 renaming its
// own comm to the allowlisted name via prctl(PR_SET_NAME) must NOT be exempt.
func TestAllowlisted_TrustedDirectoryBinaryWithAnotherNameIsNotExempt(t *testing.T) {
	cp := newTestControlPlane(t)
	withAllowlist(t, cp, "evil", "/usr/bin/python3", nil) // comm "evil", but the binary is python3
	cp, got := enterBorderlandsWith(t, cp)
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("a trusted-directory binary that merely renamed itself must still be contained")
	}
}

func TestAllowlisted_NotRootOwnedIsNotExempt(t *testing.T) {
	cp := newTestControlPlane(t)
	withAllowlist(t, cp, "evil", "/usr/bin/evil", nil)
	exeOwnedByRoot = func(string) bool { return false } // planted/replaced by an unprivileged user
	cp, got := enterBorderlandsWith(t, cp)
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("a binary that is not root-owned and sealed must not be exempt")
	}
}

func TestExeMatchesName(t *testing.T) {
	for _, c := range []struct {
		exe, comm, path string
		want            bool
	}{
		{"/usr/sbin/sshd", "sshd", "", true},
		{"/usr/lib/systemd/systemd", "systemd", "", true},
		{"/usr/bin/python3", "sshd", "", false},
		{"/usr/bin/networkd-dispatcher", "networkd-dispat", "", true}, // comm is truncated to 15 bytes
		{"/usr/sbin/sshd", "sshd", "/usr/sbin/sshd", true},
		{"/usr/bin/sshd", "sshd", "/usr/sbin/sshd", false}, // exact path pinned
	} {
		if got := exeMatchesName(c.exe, c.comm, c.path); got != c.want {
			t.Errorf("exeMatchesName(%q,%q,%q) = %v, want %v", c.exe, c.comm, c.path, got, c.want)
		}
	}
}
