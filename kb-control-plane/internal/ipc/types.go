package ipc

import "fmt"

// ContainmentCmdMsg mirrors C's `struct kb_wire_containment_cmd` exactly.
// C side: uint32_t pid; uint32_t level; char reason[64];
// Total payload size = 4 + 4 + 64 = 72 bytes.
type ContainmentCmdMsg struct {
	PID    uint32
	Level  uint32
	Reason [64]byte
}

type ProcessExitMsg struct {
	PID        uint32
	ExitTimeNs int64
	ExitCode   uint32
}

// ContainmentAckMsg mirrors C's `struct kb_wire_containment_ack`
// (kb_bridge.h), msg_type 10, sensor -> kbd on kbct.sock (the control connection the command arrived on; accepted on kbd.sock too for older sensors): what the sensor did
// with one containment command. Payload after the 4-byte header is
// pid(4) + level(4) + decision(4) = 12 bytes.
type ContainmentAckMsg struct {
	PID      uint32
	Level    uint32
	Decision uint32
}

// Containment ack decisions — keep in sync with enum kb_ack_decision in
// kb-core/userspace/bridge/kb_bridge.h.
const (
	ContainmentAckApplied          uint32 = 0 // map entry written (level > 0) or removed (level 0)
	ContainmentAckCPMKernelThread  uint32 = 1
	ContainmentAckCPMPid1          uint32 = 2
	ContainmentAckCPMProtectedPID  uint32 = 3
	ContainmentAckCPMProtectedExec uint32 = 4
	ContainmentAckCWPPath          uint32 = 5
	ContainmentAckCWPHash          uint32 = 6
	ContainmentAckMapUpdateFailed  uint32 = 7
)

// AckDecisionString names an ack decision for logs, audit entries and errors.
// Unknown values are reported as such, never as applied.
func AckDecisionString(d uint32) string {
	switch d {
	case ContainmentAckApplied:
		return "applied"
	case ContainmentAckCPMKernelThread:
		return "CPM: kernel thread"
	case ContainmentAckCPMPid1:
		return "CPM: PID 1"
	case ContainmentAckCPMProtectedPID:
		return "CPM: protected PID"
	case ContainmentAckCPMProtectedExec:
		return "CPM: protected executable"
	case ContainmentAckCWPPath:
		return "CWP: protected workload (path)"
	case ContainmentAckCWPHash:
		return "CWP: protected workload (hash-verified)"
	case ContainmentAckMapUpdateFailed:
		return "sensor failed to update contained_pids_map"
	default:
		return fmt.Sprintf("unknown decision %d", d)
	}
}

// Containment levels — keep in sync with kb_common.h
const (
	ContainmentNone      uint32 = 0
	ContainmentCgroup    uint32 = 1
	ContainmentSeccomp   uint32 = 2
	ContainmentNamespace uint32 = 3
	ContainmentTerminate uint32 = 4
)

// Message type + framing constants (must match C header)
//
// FIXED: MsgTypeContainmentCmd was 3, colliding with the (dead-code) rules
// payload's hardcoded msgTypeRules in rules.go, and NOT matching the C
// side's own KB_WIRE_MSG_CONTAINMENT_CMD (kb_bridge.h), which is 5.
// kbd_sensor.c's handle_incoming_containment_cmd() checks msg_type == 5,
// so every containment command sent with the old value 3 was silently
// dropped — kbd would log the audit entry and report success (the sensor
// never NACKs), but contained_pids_map was never actually updated,
// meaning SetContainment had never worked end-to-end. Confirmed via a
// live test: kbd logged SET_CONTAINMENT_SECCOMP for a real PID, but
// `bpftool map dump` of contained_pids_map on the sensor came back empty.
const (
	MsgMagic              uint16 = 0x4B42
	MsgTypeContainmentCmd byte   = 5
	MsgTypeProcessExit    byte   = 4
	// MsgTypeContainmentAck is sensor -> kbd (kbct.sock, kbd.sock for older sensors), unlike msg_type 5.
	MsgTypeContainmentAck byte = 10

	headerSize     = 4  // magic(2) + version(1) + msgtype(1)
	cmdPayloadSize = 72 // 4 + 4 + 64
)
