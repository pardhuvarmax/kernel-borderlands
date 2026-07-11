package ipc

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// buildContainmentCmdFrame constructs the expected wire bytes independently
// of SendContainmentCmd's own encoding path, matching the style used for
// ProcessState/ZoneTransition frames above. Header: magic(2) + version(1) +
// msgtype(1) = 4 bytes. Payload: pid(4) + level(4) + reason(64) = 72 bytes.
func buildContainmentCmdFrame(pid, level uint32, reason string) []byte {
	var b []byte
	b = append(b, 0x42, 0x4B) // magic, LE: 0x4B42
	b = append(b, WireVersion, MsgTypeContainmentCmd)
	b = append(b, u32(pid)...)
	b = append(b, u32(level)...)

	reasonBuf := make([]byte, 64)
	copy(reasonBuf, reason) // truncates naturally if reason > 64 bytes
	b = append(b, reasonBuf...)
	return b
}

func TestContainmentCmdFrameIsExactly72BytePayload(t *testing.T) {
	frame := buildContainmentCmdFrame(1, ContainmentNone, "x")
	payloadLen := len(frame) - headerSize
	if payloadLen != cmdPayloadSize {
		t.Fatalf("payload is %d bytes, want %d — wire layout has drifted", payloadLen, cmdPayloadSize)
	}
}

// TestSendContainmentCmd_WireBytes reads the raw bytes SendContainmentCmd
// puts on the wire and compares them directly against an independently
// constructed frame, rather than decoding through the same struct type
// being tested — catching bugs that a round-trip test would miss (e.g. if
// both the encoder and a matching decoder shared a wrong offset).
func TestSendContainmentCmd_WireBytes(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	l := &Listener{
		conns: map[net.Conn]bool{serverConn: true},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- l.SendContainmentCmd(42, ContainmentCgroup, "oom")
	}()

	// Length prefix
	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	wantLen := uint32(headerSize + cmdPayloadSize)
	if length != wantLen {
		t.Errorf("length prefix = %d, want %d", length, wantLen)
	}

	// Header + payload
	got := make([]byte, headerSize+cmdPayloadSize)
	if _, err := readFull(clientConn, got); err != nil {
		t.Fatalf("reading frame: %v", err)
	}

	want := buildContainmentCmdFrame(42, ContainmentCgroup, "oom")
	if !bytesEqual(got, want) {
		t.Errorf("frame bytes mismatch\ngot:  %x\nwant: %x", got, want)
	}

	// Decode-back assertion: confirms the bytes on the wire actually
	// deserialize into the correct struct fields — the same thing
	// Pardhu's C-side recv() will do. A byte-literal match alone could
	// pass even if e.g. PID and Level were swapped but happened to
	// produce identical bytes in some degenerate case, or if a future
	// refactor changes ContainmentCmdMsg's field order without updating
	// buildContainmentCmdFrame to match.
	var decoded ContainmentCmdMsg
	payloadBytes := got[headerSize:]
	if err := binary.Read(bytes.NewReader(payloadBytes), binary.LittleEndian, &decoded); err != nil {
		t.Fatalf("decoding payload back into ContainmentCmdMsg: %v", err)
	}
	if decoded.PID != 42 {
		t.Errorf("decoded PID = %d, want 42", decoded.PID)
	}
	if decoded.Level != ContainmentCgroup {
		t.Errorf("decoded Level = %d, want %d", decoded.Level, ContainmentCgroup)
	}
	wantReason := [64]byte{}
	copy(wantReason[:], "oom")
	if decoded.Reason != wantReason {
		t.Errorf("decoded Reason = %q, want %q", decoded.Reason, wantReason)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("SendContainmentCmd returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendContainmentCmd did not return in time")
	}
}

func TestSendContainmentCmd_NoClients(t *testing.T) {
	l := &Listener{conns: map[net.Conn]bool{}}

	if err := l.SendContainmentCmd(1, ContainmentNone, "n/a"); err == nil {
		t.Fatal("expected error when no clients connected, got nil")
	}
}

func TestSendContainmentCmd_LongReasonTruncates(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	l := &Listener{conns: map[net.Conn]bool{serverConn: true}}
	longReason := strings.Repeat("x", 200)

	errCh := make(chan error, 1)
	go func() {
		errCh <- l.SendContainmentCmd(1, ContainmentTerminate, longReason)
	}()

	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	got := make([]byte, headerSize+cmdPayloadSize)
	if _, err := readFull(clientConn, got); err != nil {
		t.Fatalf("reading frame: %v", err)
	}

	// Reason field should be exactly 64 'x' bytes — no overflow, no panic.
	wantReason := strings.Repeat("x", 64)
	gotReason := got[headerSize+8 : headerSize+8+64] // skip pid(4)+level(4)
	if string(gotReason) != wantReason {
		t.Errorf("reason field = %q, want 64 'x' bytes", gotReason)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("SendContainmentCmd returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendContainmentCmd did not return in time")
	}
}

// TestSendContainmentCmd_ExactlyBoundaryReason checks the off-by-one edge:
// a reason of exactly 64 bytes should pass through unmodified, not be
// truncated to 63 or overflow into a 65th byte.
func TestSendContainmentCmd_ExactlyBoundaryReason(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	l := &Listener{conns: map[net.Conn]bool{serverConn: true}}
	exact := strings.Repeat("y", 64)

	errCh := make(chan error, 1)
	go func() {
		errCh <- l.SendContainmentCmd(1, ContainmentNamespace, exact)
	}()

	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	got := make([]byte, headerSize+cmdPayloadSize)
	if _, err := readFull(clientConn, got); err != nil {
		t.Fatalf("reading frame: %v", err)
	}

	gotReason := got[headerSize+8 : headerSize+8+64]
	if string(gotReason) != exact {
		t.Errorf("reason field = %q, want exact 64-byte string unmodified", gotReason)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("SendContainmentCmd returned error: %v", err)
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}