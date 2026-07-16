package ipc

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

	headerSize     = 4  // magic(2) + version(1) + msgtype(1)
	cmdPayloadSize = 72 // 4 + 4 + 64
)
