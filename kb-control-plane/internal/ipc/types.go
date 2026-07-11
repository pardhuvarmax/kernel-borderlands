package ipc

// ContainmentCmdMsg mirrors C's `struct kb_wire_containment_cmd` exactly.
// C side: uint32_t pid; uint32_t level; char reason[64];
// Total payload size = 4 + 4 + 64 = 72 bytes.
type ContainmentCmdMsg struct {
	PID    uint32
	Level  uint32
	Reason [64]byte
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
const (
	MsgMagic             uint16 = 0x4B42
	MsgTypeContainmentCmd byte  = 3
	MsgTypeProcessExit    byte  = 4

	headerSize  = 4  // magic(2) + version(1) + msgtype(1)
	cmdPayloadSize = 72 // 4 + 4 + 64
)