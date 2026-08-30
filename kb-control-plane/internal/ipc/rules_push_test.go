package ipc

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- Dynamic rules push (docs/development/core-control/dynamic-rules.md):
// previously SendRulesPayload was fully implemented but had zero
// production callers — the sensor already reads for a rules push at
// connect time (kbd_sensor.c's read_rules_from_bridge) and falls back to
// its compiled-in defaults, but nothing on the Go side ever sent one. ---

func writeTempRulesYAML(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write temp rules.yaml: %v", err)
	}
	return path
}

const testRulesYAML = `
rules:
  - name: reverse_shell_compromised
    description: "test rule"
    required_flags:
      - KB_EV_OUTBOUND_CONNECT
      - KB_EV_SPAWNED_SHELL
    sequence:
      - KB_SEQ_OUTBOUND_CONNECT
      - KB_SEQ_EXEC_SHELL
    window_seconds: 60
    target_state: KB_STATE_COMPROMISED
    reason: KB_REASON_REVERSE_SHELL_CHAIN
    min_source_state: KB_STATE_BORDERLANDS
`

func TestPushConnectTimeFrames_SendsRulesWhenConfigured(t *testing.T) {
	rulesPath := writeTempRulesYAML(t, testRulesYAML)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	l := &Listener{conns: map[net.Conn]bool{}}
	l.SetRulesPath(rulesPath)

	go l.pushConnectTimeFrames(serverConn)

	var length uint32
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	if length < 8 {
		t.Fatalf("payload length %d too short for a rules frame header", length)
	}

	buf := make([]byte, length)
	if _, err := readFull(clientConn, buf); err != nil {
		t.Fatalf("reading frame: %v", err)
	}

	magic := binary.LittleEndian.Uint16(buf[0:2])
	version := buf[2]
	msgType := buf[3]
	ruleCount := binary.LittleEndian.Uint32(buf[4:8])

	if magic != WireMagic {
		t.Errorf("magic = %#x, want %#x", magic, WireMagic)
	}
	if version != WireVersion {
		t.Errorf("version = %d, want %d", version, WireVersion)
	}
	const msgTypeRules = 3
	if msgType != msgTypeRules {
		t.Errorf("msg_type = %d, want %d (rules)", msgType, msgTypeRules)
	}
	if ruleCount != 1 {
		t.Errorf("rule_count = %d, want 1", ruleCount)
	}
}

// TestPushConnectTimeFrames_RulesSentBeforeSensitivePaths guards the exact
// bug class this feature shipped with once already: kbd_sensor.c's
// connect-time handshake calls read_rules_from_bridge() first, and only
// read_sensitive_paths_from_bridge() (called second) has a stash-based
// fallback for "the wrong frame arrived here." Swapping the send order
// silently corrupts the sensor's later wire framing (it never fully
// consumes one of the two frames) without any test failure on the Go side
// alone — the only way to catch it is asserting the actual wire order.
func TestPushConnectTimeFrames_RulesSentBeforeSensitivePaths(t *testing.T) {
	rulesPath := writeTempRulesYAML(t, testRulesYAML)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	l := &Listener{conns: map[net.Conn]bool{}}
	l.SetRulesPath(rulesPath)
	l.SetSensitivePaths([]string{"/etc/shadow"})

	go l.pushConnectTimeFrames(serverConn)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	readFrame := func() []byte {
		var length uint32
		if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
			t.Fatalf("reading length prefix: %v", err)
		}
		buf := make([]byte, length)
		if _, err := readFull(clientConn, buf); err != nil {
			t.Fatalf("reading frame: %v", err)
		}
		return buf
	}

	first := readFrame()
	second := readFrame()

	const msgTypeRules = 3
	if got := first[3]; got != msgTypeRules {
		t.Errorf("first frame's msg_type = %d, want %d (rules) — kbd_sensor.c's read_rules_from_bridge() runs first and has no fallback if the wrong frame arrives", got, msgTypeRules)
	}
	if got := second[3]; got != KBWireMsgSensitivePaths {
		t.Errorf("second frame's msg_type = %d, want %d (sensitive paths)", got, KBWireMsgSensitivePaths)
	}
}

func TestPushConnectTimeFrames_NoRulesPathConfigured_SendsNothing(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	l := &Listener{conns: map[net.Conn]bool{}}
	// rulesPath left unset (empty) — no rules.yaml configured.

	done := make(chan struct{})
	go func() {
		l.pushConnectTimeFrames(serverConn)
		close(done)
	}()
	<-done

	clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := clientConn.Read(buf); err == nil {
		t.Fatal("expected no data written when no rules path is configured, but got data")
	}
}

func TestPushConnectTimeFrames_UnreadableRulesPath_DoesNotPanicOrBlock(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	l := &Listener{conns: map[net.Conn]bool{}}
	l.SetRulesPath("/nonexistent/path/rules.yaml")

	done := make(chan struct{})
	go func() {
		l.pushConnectTimeFrames(serverConn) // must not panic
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pushConnectTimeFrames did not return in time for an unreadable rules path")
	}
}
