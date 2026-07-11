package enforcement

import (
	"fmt"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

type Enforcer struct {
	listener *ipc.Listener
}

func NewEnforcer(l *ipc.Listener) *Enforcer {
	return &Enforcer{listener: l}
}

// Contain routes an operator-triggered containment request to the C sensor
// via the UDS feedback channel. `level` should be one of ipc.Containment*.
//
// ContainmentNone (level 0) is NOT a no-op: it sends a level-0 wire message
// so the C sensor can call bpf_map_delete_elem on its contained_pids_map.
// Without this, a "restore" from the dashboard would update the Go-side store
// but leave the BPF map entry intact, keeping the PID kernel-contained forever.
func (e *Enforcer) Contain(pid uint32, level uint32, reason string) error {
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