package enforcement

import (
	"fmt"
	"os"
	"strings"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/store"
)

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
		return nil
	default:
		return fmt.Errorf("enforcement: unknown containment level %d", level)
	}
}