package ipc

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSendRulesPayload(t *testing.T) {
	// Create a temporary directory for test config
	tmpDir, err := os.MkdirTemp("", "kb-rules-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write a mock rules.yaml
	rulesYAMLPath := filepath.Join(tmpDir, "rules.yaml")
	mockYAML := `
rules:
  - name: test_rule
    description: "This is a test rule"
    required_flags:
      - KB_EV_OUTBOUND_CONNECT
      - KB_EV_RWX_MAPPING
    optional_flags:
      - KB_EV_EXEC_FROM_TMP
    optional_min: 1
    sequence:
      - KB_SEQ_EXEC
      - KB_SEQ_OUTBOUND_CONNECT
    window_seconds: 30
    target_state: KB_STATE_COMPROMISED
    reason: KB_REASON_KNOWN_IOC_SEQUENCE
    min_source_state: KB_STATE_SAFE
`
	if err := os.WriteFile(rulesYAMLPath, []byte(mockYAML), 0644); err != nil {
		t.Fatalf("failed to write mock yaml: %v", err)
	}

	// Set up a mock local pipe/connection to write to
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Launch SendRulesPayload in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- SendRulesPayload(c1, rulesYAMLPath)
	}()

	// Read from c2 (receiver side)
	// 1. Read prefix length
	var length uint32
	if err := binary.Read(c2, binary.LittleEndian, &length); err != nil {
		t.Fatalf("failed to read prefix length: %v", err)
	}

	// 2. Read full payload
	payload := make([]byte, length)
	n, err := c2.Read(payload)
	if err != nil {
		t.Fatalf("failed to read payload: %v", err)
	}
	if uint32(n) != length {
		t.Fatalf("read %d bytes, expected %d", n, length)
	}

	// Check SendRulesPayload didn't error out
	if err := <-errChan; err != nil {
		t.Fatalf("SendRulesPayload failed: %v", err)
	}

	// 3. Parse header from payload
	magic := binary.LittleEndian.Uint16(payload[0:2])
	version := payload[2]
	msgType := payload[3]

	if magic != WireMagic {
		t.Errorf("magic = 0x%X, want 0x%X", magic, WireMagic)
	}
	if version != WireVersion {
		t.Errorf("version = %d, want %d", version, WireVersion)
	}
	if msgType != uint8(3) {
		t.Errorf("msgType = %d, want 3 (rules payload)", msgType)
	}

	// 4. Parse rule count
	ruleCount := binary.LittleEndian.Uint32(payload[4:8])
	if ruleCount != 1 {
		t.Errorf("ruleCount = %d, want 1", ruleCount)
	}

	// 5. Verify serialized rule size and offsets
	// Total payload size should be 8 (header) + ruleCount * 220 (C sizeof struct kb_wire_attack_rule)
	expectedSize := 8 + 1*220
	if len(payload) != expectedSize {
		t.Errorf("payload length = %d, want %d", len(payload), expectedSize)
	}

	// Unpack name (first 32 bytes)
	nameBytes := payload[8 : 8+32]
	var name string
	for i, b := range nameBytes {
		if b == 0 {
			name = string(nameBytes[:i])
			break
		}
	}
	if name != "test_rule" {
		t.Errorf("rule name = %q, want \"test_rule\"", name)
	}
}
