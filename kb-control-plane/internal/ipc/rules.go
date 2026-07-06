package ipc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// KBWireAttackRule represents the 220-byte packed binary structure sent over the wire to kbd_sensor.
type KBWireAttackRule struct {
	Name           [32]byte
	Description    [128]byte
	RequiredFlags  uint64
	OptionalFlags  uint64
	OptionalMin    int32
	Sequence       [16]byte
	SequenceLen    int32
	WindowNs       uint64
	TargetState    uint32
	Reason         uint32
	MinSourceState uint32
}

// YAMLRule represents a single rule definition inside rules.yaml.
type YAMLRule struct {
	Name           string   `yaml:"name"`
	Description    string   `yaml:"description"`
	RequiredFlags  []string `yaml:"required_flags"`
	OptionalFlags  []string `yaml:"optional_flags"`
	OptionalMin    int32    `yaml:"optional_min"`
	Sequence       []string `yaml:"sequence"`
	WindowSeconds  uint64   `yaml:"window_seconds"`
	TargetState    string   `yaml:"target_state"`
	Reason         string   `yaml:"reason"`
	MinSourceState string   `yaml:"min_source_state"`
}

// YAMLPolicy represents the wrapper structure for rules.yaml.
type YAMLPolicy struct {
	Rules []YAMLRule `yaml:"rules"`
}

// FlagMap maps YAML string representations of evidence flags to internal engine uint64 bitmasks.
var FlagMap = map[string]uint64{
	"KB_EV_NONE":                   0,
	"KB_EV_EXEC_FROM_TMP":          1 << 0,
	"KB_EV_EXEC_FROM_PROC":         1 << 1,
	"KB_EV_SPAWNED_SHELL":          1 << 2,
	"KB_EV_ANOMALOUS_PARENT":       1 << 3,
	"KB_EV_RAPID_EXEC_BURST":       1 << 4,
	"KB_EV_EXECVEAT":               1 << 5,
	"KB_EV_PRIVILEGE_GAINED":       1 << 8,
	"KB_EV_ROOT_ACHIEVED":          1 << 9,
	"KB_EV_CAP_GAINED":             1 << 10,
	"KB_EV_SETUID_ABUSE":           1 << 11,
	"KB_EV_RWX_MAPPING":            1 << 16,
	"KB_EV_ANON_EXEC":              1 << 17,
	"KB_EV_WX_TRANSITION":          1 << 18,
	"KB_EV_LARGE_ANON_EXEC":        1 << 19,
	"KB_EV_PROC_MEM_WRITE":         1 << 20,
	"KB_EV_PROCESS_VM_WRITE":       1 << 21,
	"KB_EV_SHADOW_ACCESS":          1 << 24,
	"KB_EV_PASSWD_ACCESS":          1 << 25,
	"KB_EV_SUDOERS_ACCESS":         1 << 26,
	"KB_EV_SSH_KEY_ACCESS":         1 << 27,
	"KB_EV_CRON_WRITE":             1 << 28,
	"KB_EV_BINARY_PATH_WRITE":      1 << 29,
	"KB_EV_OUTBOUND_CONNECT":       1 << 32,
	"KB_EV_NONSTANDARD_PORT":       1 << 33,
	"KB_EV_C2_CANDIDATE_PORT":      1 << 34,
	"KB_EV_BIND_LISTENER":          1 << 35,
	"KB_EV_DNS_TUNNEL_SUSPECT":     1 << 36,
	"KB_EV_RAPID_CONNECT_BURST":    1 << 37,
	"KB_EV_HIGH_SYSCALL_ENTROPY":   1 << 40,
	"KB_EV_PTRACE_USED":            1 << 41,
	"KB_EV_SECCOMP_BYPASS_ATTEMPT": 1 << 42,
	"KB_EV_UNUSUAL_SYSCALL_SEQ":    1 << 43,
}

// SeqMap maps YAML string representations of sequence events to their internal C byte IDs.
var SeqMap = map[string]byte{
	"KB_SEQ_NONE":             0,
	"KB_SEQ_EXEC":             1,
	"KB_SEQ_EXEC_SHELL":       2,
	"KB_SEQ_EXIT":             3,
	"KB_SEQ_PRIVILEGE_UP":     4,
	"KB_SEQ_PRIVILEGE_ROOT":   5,
	"KB_SEQ_RWX_MAP":          6,
	"KB_SEQ_ANON_EXEC":        7,
	"KB_SEQ_WX_TRANSITION":    8,
	"KB_SEQ_SHADOW_ACCESS":    9,
	"KB_SEQ_SSH_KEY_ACCESS":   10,
	"KB_SEQ_OUTBOUND_CONNECT": 11,
	"KB_SEQ_NONSTD_PORT":      12,
	"KB_SEQ_C2_PORT":          13,
	"KB_SEQ_BIND_LISTEN":      14,
	"KB_SEQ_HIGH_ENTROPY":     15,
	"KB_SEQ_PTRACE":           16,
	"KB_SEQ_PROC_MEM_WRITE":   17,
	"KB_SEQ_CRED_FILE":        18,
	"KB_SEQ_RAPID_EXEC":       19,
	"KB_SEQ_RAPID_CONNECT":    20,
}

// StateMap maps YAML string representations of behavior states to their internal C uint32 IDs.
var StateMap = map[string]uint32{
	"KB_STATE_SAFE":        0,
	"KB_STATE_OBSERVED":    1,
	"KB_STATE_SUSPICIOUS":  2,
	"KB_STATE_BORDERLANDS": 3,
	"KB_STATE_COMPROMISED": 4,
	"KB_STATE_CONTAINED":   5,
	"KB_STATE_RECOVERING":  6,
}

// ReasonMap maps YAML string representations of transition reasons to their internal C uint32 IDs.
var ReasonMap = map[string]uint32{
	"KB_REASON_NONE":                   0,
	"KB_REASON_FIRST_ANOMALY":          1,
	"KB_REASON_OUTBOUND_CONNECT":       2,
	"KB_REASON_PRIVILEGE_CHANGE":       3,
	"KB_REASON_HIGH_SYSCALL_ENTROPY":   4,
	"KB_REASON_MULTI_ANOMALY":          10,
	"KB_REASON_PRIVILEGE_PLUS_NETWORK": 11,
	"KB_REASON_CRED_FILE_ACCESS":       12,
	"KB_REASON_ANON_EXEC_MAPPING":      13,
	"KB_REASON_SHELL_SPAWN":            14,
	"KB_REASON_RWX_MEMORY":             20,
	"KB_REASON_ATTACK_CHAIN_PARTIAL":   21,
	"KB_REASON_PTRACE_INJECTION":       22,
	"KB_REASON_C2_PORT_CONNECT":        23,
	"KB_REASON_PROC_MEM_WRITE":         24,
	"KB_REASON_RAPID_CONNECT_BURST":    25,
	"KB_REASON_REVERSE_SHELL_CHAIN":    30,
	"KB_REASON_INJECTION_CHAIN":        31,
	"KB_REASON_ESCALATION_EXFIL_CHAIN": 32,
	"KB_REASON_FULL_ATTACK_CHAIN":      33,
	"KB_REASON_KNOWN_IOC_SEQUENCE":     40,
	"KB_REASON_EVIDENCE_INSUFFICIENT":  50,
	"KB_REASON_OPERATOR_OVERRIDE":      51,
}

func parseFlags(list []string) uint64 {
	var mask uint64
	for _, f := range list {
		if val, ok := FlagMap[f]; ok {
			mask |= val
		} else if f == "0xFFFFFFFFFFFFFFFF" {
			mask = 0xFFFFFFFFFFFFFFFF
		}
	}
	return mask
}

func parseSequence(list []string) ([16]byte, int32) {
	var seq [16]byte
	length := 0
	for i, s := range list {
		if i >= 16 {
			break
		}
		if val, ok := SeqMap[s]; ok {
			seq[i] = val
			length++
		}
	}
	return seq, int32(length)
}

// SendRulesPayload reads the rules from the specified YAML file path, compiles them into packed structures, and transmits them over the bridge.
func SendRulesPayload(conn net.Conn, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		// Try fallback relative path
		data, err = os.ReadFile("../" + path)
		if err != nil {
			return fmt.Errorf("read rules yaml: %w", err)
		}
	}

	var policy YAMLPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("unmarshal rules yaml: %w", err)
	}

	rules := make([]KBWireAttackRule, 0, len(policy.Rules))
	for _, yr := range policy.Rules {
		var name [32]byte
		copy(name[:], yr.Name)

		var desc [128]byte
		copy(desc[:], yr.Description)

		reqFlags := parseFlags(yr.RequiredFlags)
		optFlags := parseFlags(yr.OptionalFlags)
		seq, seqLen := parseSequence(yr.Sequence)

		targetState := StateMap[yr.TargetState]
		reason := ReasonMap[yr.Reason]
		minSourceState := StateMap[yr.MinSourceState]

		rules = append(rules, KBWireAttackRule{
			Name:           name,
			Description:    desc,
			RequiredFlags:  reqFlags,
			OptionalFlags:  optFlags,
			OptionalMin:    yr.OptionalMin,
			Sequence:       seq,
			SequenceLen:    seqLen,
			WindowNs:       yr.WindowSeconds * 1000000000,
			TargetState:    targetState,
			Reason:         reason,
			MinSourceState: minSourceState,
		})
	}

	// Build payload buffer
	var buf bytes.Buffer

	// Message type for Rules payload is 3
	const msgTypeRules uint8 = 3

	// Write rules header: magic (0x4B42), version (3), message type (3)
	binary.Write(&buf, binary.LittleEndian, WireMagic)
	binary.Write(&buf, binary.LittleEndian, WireVersion)
	binary.Write(&buf, binary.LittleEndian, msgTypeRules)

	// Write rule count
	binary.Write(&buf, binary.LittleEndian, uint32(len(rules)))

	// Write each rule struct
	for _, rule := range rules {
		binary.Write(&buf, binary.LittleEndian, rule)
	}

	payloadBytes := buf.Bytes()
	payloadLen := uint32(len(payloadBytes))

	// Send length prefix (4 bytes) followed by payload bytes
	var prefixBuf [4]byte
	binary.LittleEndian.PutUint32(prefixBuf[:], payloadLen)

	if _, err := conn.Write(prefixBuf[:]); err != nil {
		return fmt.Errorf("write prefix: %w", err)
	}

	if _, err := conn.Write(payloadBytes); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	log.Printf("[IPC] Sent %d dynamic rules to kbd_sensor", len(rules))
	return nil
}
