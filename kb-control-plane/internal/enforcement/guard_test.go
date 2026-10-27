package enforcement

import (
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// fakeProc builds <root>/<pid>/{exe,stat}. exe is a symlink to target; if
// target is a real file (hash tests) the link resolves, otherwise it dangles,
// which Readlink does not care about.
func fakeProc(t *testing.T, pid uint32, target string, flags uint64) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, strconv.Itoa(int(pid)))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if target != "" {
		if err := os.Symlink(target, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	stat := strconv.Itoa(int(pid)) + " (comm with ) paren) S 1 1 1 0 -1 " + strconv.FormatUint(flags, 10) + " 0 0\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func wantRefusal(t *testing.T, err error, gate string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %s refusal, got nil (the process would be killed)", gate)
	}
	if !strings.Contains(err.Error(), gate) || !strings.Contains(err.Error(), "refusing to terminate") {
		t.Fatalf("got %q, want a %s refusal", err, gate)
	}
}

func TestClassify_Pid1Refused(t *testing.T) {
	wantRefusal(t, classifyForTerminate(t.TempDir(), 1, nil), "CPM")
}

func TestClassify_KernelThreadFlagRefused(t *testing.T) {
	root := fakeProc(t, 2222, "/usr/bin/anything", pfKthread)
	wantRefusal(t, classifyForTerminate(root, 2222, nil), "CPM")
}

func TestClassify_UnresolvableExeFailsClosed(t *testing.T) {
	root := fakeProc(t, 3333, "", 0) // process dir exists, no exe link
	wantRefusal(t, classifyForTerminate(root, 3333, nil), "CPM")
}

func TestClassify_MissingProcessIsGoneNotRefused(t *testing.T) {
	err := classifyForTerminate(t.TempDir(), 4444, nil)
	if !errors.Is(err, errProcessGone) {
		t.Fatalf("got %v, want errProcessGone", err)
	}
}

func TestClassify_ProtectedExecutablesRefused(t *testing.T) {
	for _, exe := range []string{
		"/usr/lib/systemd/systemd-logind",          // sensor floor
		"/usr/bin/kbd",                             // packaged path, not in the sensor floor
		"/usr/bin/kbctl",                           // CPM.md §5.2
		"/usr/lib/systemd/systemd-udevd (deleted)", // replaced binary
	} {
		root := fakeProc(t, 5555, exe, 0)
		wantRefusal(t, classifyForTerminate(root, 5555, nil), "CPM")
	}
}

func TestClassify_OrdinaryProcessAllowed(t *testing.T) {
	root := fakeProc(t, 6666, "/usr/bin/curl", 0)
	if err := classifyForTerminate(root, 6666, nil); err != nil {
		t.Fatalf("an unprotected process was refused: %v", err)
	}
}

func TestClassify_CWPPathTierRefused(t *testing.T) {
	root := fakeProc(t, 7777, "/opt/billing/worker", 0)
	reg := []ipc.CWPWorkloadEntry{{Path: "/opt/billing/worker", IdentityTier: 0}}
	wantRefusal(t, classifyForTerminate(root, 7777, reg), "CWP")
}

func TestClassify_CWPHashTier(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "worker")
	if err := os.WriteFile(bin, []byte("registered image"), 0o755); err != nil {
		t.Fatal(err)
	}
	root := fakeProc(t, 8888, bin, 0)
	good := sha256.Sum256([]byte("registered image"))

	t.Run("matching hash is protected", func(t *testing.T) {
		reg := []ipc.CWPWorkloadEntry{{Path: bin, IdentityTier: 1, ExpectedHash: good}}
		wantRefusal(t, classifyForTerminate(root, 8888, reg), "CWP")
	})
	t.Run("different binary at the same path is not exempt (spoof)", func(t *testing.T) {
		other := sha256.Sum256([]byte("something else"))
		reg := []ipc.CWPWorkloadEntry{{Path: bin, IdentityTier: 1, ExpectedHash: other}}
		if err := classifyForTerminate(root, 8888, reg); err != nil {
			t.Fatalf("spoofed identity should not be protected: %v", err)
		}
	})
	t.Run("entry without a hash fails closed", func(t *testing.T) {
		reg := []ipc.CWPWorkloadEntry{{Path: bin, IdentityTier: 1}}
		wantRefusal(t, classifyForTerminate(root, 8888, reg), "CWP")
	})
	t.Run("unreadable image fails closed", func(t *testing.T) {
		gone := fakeProc(t, 9999, "/nonexistent/worker", 0)
		reg := []ipc.CWPWorkloadEntry{{Path: "/nonexistent/worker", IdentityTier: 1, ExpectedHash: good}}
		wantRefusal(t, classifyForTerminate(gone, 9999, reg), "CWP")
	})
}

func TestSamePathKey_UsesSensorKeyLength(t *testing.T) {
	long := "/opt/" + strings.Repeat("a", 80)
	if !samePathKey(long, long[:63]+"different-tail") {
		t.Error("paths sharing the 63-byte sensor key must compare equal (fail closed)")
	}
	if samePathKey("/usr/bin/a", "/usr/bin/b") {
		t.Error("different short paths must not match")
	}
}

// Real pidfd path, against a child process this test owns: the gate allows
// it (sleep is not protected) and Kill ends exactly that process.
func TestPrepareTerminate_RealPidfdKillsOwnChild(t *testing.T) {
	prev := prepareTerminate
	t.Cleanup(func() { prepareTerminate = prev })
	// Use the real implementation (TestMain stubs it for everything else).
	real := realPrepareTerminate

	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill() })

	target, err := real(NewEnforcer(nil, nil), uint32(cmd.Process.Pid))
	if err != nil {
		t.Skipf("pidfd or /proc unavailable here: %v", err)
	}
	defer target.Close()
	if err := target.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	select {
	case err := <-done:
		ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("child ended with %v (state %v), want death by SIGKILL", err, cmd.ProcessState)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("child still running after Kill")
	}
}

func TestPrepareTerminate_RealRefusesPid1(t *testing.T) {
	_, err := realPrepareTerminate(NewEnforcer(nil, nil), 1)
	if err == nil {
		t.Fatal("PID 1 must never pass the gate")
	}
}
