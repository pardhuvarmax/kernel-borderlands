package enforcement

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/store"
)

// killProcess delivers SIGKILL to pid. It is a variable so tests can replace
// it: the level-4 tests use real-looking PIDs and must never signal a live
// process on the machine running them.
var killProcess = func(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}

type Enforcer struct {
	listener *ipc.Listener
	store    *store.Store
	// protectedComm is a small allowlist of critical process names that
	// may never be contained, independent of whatever kb-core's CPM gate
	// does downstream over kbct.sock (BUG-011 — the Go side previously had
	// no exemption logic of its own, relying entirely on that one hop).
	protectedComm map[string]bool
}

// NewEnforcer builds an Enforcer. store may be nil (comm-based protection
// is skipped, PID-1/self-PID protection still applies) — kept optional so
// existing callers/tests aren't forced to wire a store just to construct
// one.
func NewEnforcer(l *ipc.Listener, s *store.Store) *Enforcer {
	protected := map[string]bool{}
	names := os.Getenv("KB_PROTECTED_COMM")
	if names == "" {
		names = "systemd,kbd,kbd_sensor,init"
	}
	for _, n := range strings.Split(names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			protected[n] = true
		}
	}
	return &Enforcer{listener: l, store: s, protectedComm: protected}
}

// Contain routes an operator-triggered containment request to the C sensor
// via the UDS feedback channel. `level` should be one of ipc.Containment*.
//
// ContainmentNone (level 0) is NOT a no-op: it sends a level-0 wire message
// so the C sensor can call bpf_map_delete_elem on its contained_pids_map.
// Without this, a "restore" from the dashboard would update the Go-side store
// but leave the BPF map entry intact, keeping the PID kernel-contained forever.
func (e *Enforcer) Contain(pid uint32, level uint32, reason string) error {
	// PID-1/self-PID/protected-name gate (BUG-011). Restore (level 0) is
	// exempt — clearing containment on a protected PID is always safe and
	// matters for recovering from a bad containment call that slipped
	// through before this gate existed.
	if level != ipc.ContainmentNone {
		if pid == 1 {
			return fmt.Errorf("enforcement: refusing to contain pid 1 (init)")
		}
		if pid == uint32(os.Getpid()) {
			return fmt.Errorf("enforcement: refusing to contain self (kbd, pid=%d)", pid)
		}
		if e.store != nil {
			if cs, ok := e.store.GetProcessState(pid); ok && e.protectedComm[cs.Comm] {
				return fmt.Errorf("enforcement: refusing to contain protected process %q (pid=%d)", cs.Comm, pid)
			}
		}
	}

	switch level {
	case ipc.ContainmentNone, ipc.ContainmentCgroup, ipc.ContainmentSeccomp,
		ipc.ContainmentNamespace, ipc.ContainmentTerminate:
		if err := e.listener.SendContainmentCmd(pid, level, reason); err != nil {
			return fmt.Errorf("enforcement: failed to send containment cmd: %w", err)
		}
		// Level 4 (Terminate) is the userspace half of a belt-and-suspenders
		// pair: the sensor records level 4 in contained_pids_map so the LSM
		// hooks deny everything, and kbd then SIGKILLs the process (see the
		// Level 4 comment in kb-core/ebpf/kbd_sensor.bpf.c). The kill only
		// happens once the command reached the sensor, so a failed send never
		// kills a process that was not also contained in the kernel. ESRCH
		// means the process already exited, which is the outcome we wanted.
		if level == ipc.ContainmentTerminate {
			if err := killProcess(int(pid)); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("enforcement: terminate cmd sent but SIGKILL to pid %d failed: %w", pid, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("enforcement: unknown containment level %d", level)
	}
}
