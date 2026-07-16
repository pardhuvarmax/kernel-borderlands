package ipc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

// KBWireMsgSensitivePaths is a fresh, unused wire msg_type. 3 is
// double-booked between the rules payload (rules.go's msgTypeRules,
// dead code) and what MsgTypeContainmentCmd (types.go) used to be before
// it was fixed to 5 to match the C side's KB_WIRE_MSG_CONTAINMENT_CMD.
// 6 is the first genuinely free value.
const KBWireMsgSensitivePaths uint8 = 6

// sensitivePathKeySize matches the fixed-size BPF map key
// (char[64] in kb-core/ebpf/kbd_sensor.bpf.c).
const sensitivePathKeySize = 64

// SendSensitivePaths frames and transmits the operator-supplied
// additions to the LSM file-block list to a single newly-connected C
// sensor. paths is expected to already be validated (see
// internal/policy.Engine.SensitivePaths) — this only re-checks the
// wire-level invariant (fits the fixed-size key) as a last-resort guard,
// it does not re-run policy validation.
func SendSensitivePaths(conn net.Conn, paths []string) error {
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, WireMagic)
	binary.Write(&buf, binary.LittleEndian, WireVersion)
	binary.Write(&buf, binary.LittleEndian, KBWireMsgSensitivePaths)

	binary.Write(&buf, binary.LittleEndian, uint32(len(paths)))

	for _, p := range paths {
		if len(p) >= sensitivePathKeySize {
			return fmt.Errorf("sensitive path %q does not fit the %d-byte wire key (should already have been rejected by policy validation)", p, sensitivePathKeySize)
		}
		var key [sensitivePathKeySize]byte
		copy(key[:], p)
		buf.Write(key[:])
	}

	payloadBytes := buf.Bytes()
	payloadLen := uint32(len(payloadBytes))

	var prefixBuf [4]byte
	binary.LittleEndian.PutUint32(prefixBuf[:], payloadLen)

	if _, err := conn.Write(prefixBuf[:]); err != nil {
		return fmt.Errorf("write prefix: %w", err)
	}
	if _, err := conn.Write(payloadBytes); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	log.Printf("[IPC] Sent %d sensitive path(s) to kbd_sensor", len(paths))
	return nil
}
