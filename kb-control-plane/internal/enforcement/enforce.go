package enforcement

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

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

	// cwpSource supplies the loaded CWP registry for the Go-side TERMINATE
	// gate (guard.go). Set once by the control plane.
	cwpMu     sync.RWMutex
	cwpSource func() []ipc.CWPWorkloadEntry

	// acks matches the sensor's CONTAINMENT_ACK replies to waiting Contain
	// calls (acks.go).
	acks *ackTracker
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
	return &Enforcer{listener: l, store: s, protectedComm: protected, acks: newAckTracker()}
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
		// TERMINATE kills, so it must pass CPM and CWP in kbd (guard.go) as
		// well as in the sensor, whose verdict comes back as an ack (acks.go).
		// The target is pinned and checked BEFORE level 4 is sent: a protected
		// process is neither contained at level 4 nor killed.
		var target terminateTarget
		var ackCh <-chan uint32
		var cancelAck func()
		if level == ipc.ContainmentTerminate {
			t, err := prepareTerminate(e, pid)
			if err != nil {
				return err
			}
			defer t.Close()
			target = t
			// Register for the sensor's reply BEFORE sending, so a fast ack
			// cannot be missed.
			ackCh, cancelAck, err = e.acks.expect(pid, level)
			if err != nil {
				return err
			}
			defer cancelAck()
		}
		if err := e.listener.SendContainmentCmd(pid, level, reason); err != nil {
			return fmt.Errorf("enforcement: failed to send containment cmd: %w", err)
		}
		// Level 4 is the userspace half of a belt-and-suspenders pair: the
		// sensor records level 4 in contained_pids_map so the LSM hooks deny
		// everything, and kbd then SIGKILLs the process (see the Level 4
		// comment in kb-core/ebpf/kbd_sensor.bpf.c). The kill only happens
		// once the process passed the Go-side gate above AND the sensor
		// reported that it applied level 4 (its own CPM/CWP gates ran and the
		// map write succeeded). A refusal, a missing ack (timeout, or a
		// sensor that predates acks) means no kill. The kill goes through the
		// pidfd so it hits exactly the process that was checked; ESRCH means
		// it already exited.
		if target != nil {
			select {
			case decision := <-ackCh:
				if decision != ipc.ContainmentAckApplied {
					return fmt.Errorf("enforcement: sensor refused terminate of pid %d (%s); not killing", pid, ipc.AckDecisionString(decision))
				}
			case <-time.After(ackTimeout):
				e.acks.markUnresolved(pid)
				return fmt.Errorf("enforcement: sensor did not acknowledge terminate of pid %d within %s; not killing (fail closed)", pid, ackTimeout)
			}
			if err := target.Kill(); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("enforcement: terminate acknowledged but SIGKILL to pid %d failed: %w", pid, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("enforcement: unknown containment level %d", level)
	}
}
