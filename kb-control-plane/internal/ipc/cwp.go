package ipc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// KBWireMsgCWPWorkloads matches kb-core/userspace/bridge/kb_bridge.h's
// KB_WIRE_MSG_CWP_WORKLOADS. The kernel/sensor side of CWP (Critical
// Workload Protection, docs/features/CWP.md) — protected_workloads_map,
// cwp_classify(), the wire receiver below — was implemented and verified
// live in kb-core already; this file is the Go-side sender that was the
// one piece still missing (docs/development/core-control/
// control-plane-catalog.md, "Explicitly Out of Scope" §CWP).
const KBWireMsgCWPWorkloads uint8 = 8

const (
	cwpWorkloadKeySize  = 64 // matches KB_CWP_WORKLOAD_KEY_SIZE
	cwpIdentityTierPath = 0  // matches CWP_IDENTITY_TIER_PATH
	cwpIdentityTierHash = 1  // matches CWP_IDENTITY_TIER_HASH
	// KB_CWP_WORKLOAD_ENTRY_SIZE = path(64) + identity_tier(1) + expected_hash(32)
	cwpWorkloadEntrySize = cwpWorkloadKeySize + 1 + sha256.Size
	// CWP_MAX_REGISTRY_ENTRIES on the C side — the wire receiver silently
	// truncates past this, so reject oversized config here instead of
	// sending entries the sensor will drop.
	cwpMaxRegistryEntries = 64
)

// CWPWorkloadEntry is the Go-side mirror of kb-core's cwp_registry_entry /
// the wire frame's per-entry layout — path + identity tier + expected
// hash. YAML-only fields (owner_team, justification) are intentionally
// not part of this struct: the wire frame has no room for them
// (KB_CWP_WORKLOAD_ENTRY_SIZE is fixed-size, path+tier+hash only) — see
// CWP.md §9's alerting escalation, explicitly deferred on both sides.
type CWPWorkloadEntry struct {
	Path         string
	IdentityTier uint8 // cwpIdentityTierPath or cwpIdentityTierHash
	ExpectedHash [sha256.Size]byte
}

// cwpWorkloadYAML mirrors CWP.md §12.1's YAML schema. OwnerTeam/
// Justification are parsed and logged (operator documentation value,
// consistent with the spec's intent) but not sent over the wire — the C
// side has nowhere to put them yet (§9 alerting escalation, deferred).
type cwpWorkloadYAML struct {
	Path          string `yaml:"path"`
	IdentityTier  string `yaml:"identity_tier"` // "path" or "hash"
	ExpectedHash  string `yaml:"expected_hash"` // hex-encoded SHA-256; optional for identity_tier=hash (see LoadWorkloadsYAML)
	OwnerTeam     string `yaml:"owner_team"`
	Justification string `yaml:"justification"`
}

type cwpWorkloadsYAML struct {
	CriticalWorkloads []cwpWorkloadYAML `yaml:"critical_workloads"`
}

// LoadWorkloadsYAML reads and validates a CWP workloads config file
// (config/workloads.yaml by convention, CWP.md §12.1's schema). For
// identity_tier: hash entries with no explicit expected_hash, the hash is
// computed locally by reading the file at Path — kbd runs on the same
// host as the sensor, so this is a simpler, equally valid default than
// requiring every operator to precompute and paste a hex digest (the
// spec's expected_hash_source: build-pipeline is one option among
// several, not a hard requirement). A missing/unreadable file for a
// hash-tier entry is a hard error — silently registering a path-tier
// fallback would quietly weaken a policy the operator explicitly asked
// to be hash-verified.
func LoadWorkloadsYAML(path string) ([]CWPWorkloadEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read workloads yaml: %w", err)
	}

	var doc cwpWorkloadsYAML
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal workloads yaml: %w", err)
	}

	if len(doc.CriticalWorkloads) > cwpMaxRegistryEntries {
		return nil, fmt.Errorf("workloads yaml: %d entries exceeds the sensor's %d-entry registry capacity (CWP_MAX_REGISTRY_ENTRIES)", len(doc.CriticalWorkloads), cwpMaxRegistryEntries)
	}

	entries := make([]CWPWorkloadEntry, 0, len(doc.CriticalWorkloads))
	for _, w := range doc.CriticalWorkloads {
		if w.Path == "" {
			return nil, fmt.Errorf("workloads yaml: entry with empty path")
		}
		if len(w.Path) >= cwpWorkloadKeySize {
			return nil, fmt.Errorf("workloads yaml: path %q does not fit the %d-byte wire key", w.Path, cwpWorkloadKeySize)
		}

		entry := CWPWorkloadEntry{Path: w.Path}

		switch w.IdentityTier {
		case "", "path":
			entry.IdentityTier = cwpIdentityTierPath
		case "hash":
			entry.IdentityTier = cwpIdentityTierHash
			if w.ExpectedHash != "" {
				h, err := hex.DecodeString(w.ExpectedHash)
				if err != nil || len(h) != sha256.Size {
					return nil, fmt.Errorf("workloads yaml: entry %q has invalid expected_hash (want %d-byte hex): %w", w.Path, sha256.Size, err)
				}
				copy(entry.ExpectedHash[:], h)
			} else {
				sum, err := hashFile(w.Path)
				if err != nil {
					return nil, fmt.Errorf("workloads yaml: entry %q is identity_tier=hash with no expected_hash override, and hashing %s failed: %w", w.Path, w.Path, err)
				}
				entry.ExpectedHash = sum
				log.Printf("[CWP] computed expected_hash for %s locally: %x", w.Path, sum)
			}
		default:
			return nil, fmt.Errorf("workloads yaml: entry %q has invalid identity_tier %q (want \"path\" or \"hash\")", w.Path, w.IdentityTier)
		}

		entries = append(entries, entry)
	}
	return entries, nil
}

func hashFile(path string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	data, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	out = sha256.Sum256(data)
	return out, nil
}

// SendCWPWorkloads frames and transmits the operator-configured protected
// workload registry to a single connected C sensor, over the same
// KB_WIRE_MSG_CWP_WORKLOADS shape kbd_sensor.c's apply_cwp_workloads_frame
// already parses. Unlike the rules/sensitive-paths pushes, the sensor
// reads for this continuously at runtime (non-blocking MSG_PEEK poll, not
// just once at connect time — see read_cwp_workloads_from_bridge), so
// this is safe to call at any point after connection, not only during the
// initial handshake.
func SendCWPWorkloads(conn net.Conn, entries []CWPWorkloadEntry) error {
	if len(entries) > cwpMaxRegistryEntries {
		return fmt.Errorf("ipc: %d workload entries exceeds the sensor's %d-entry registry capacity", len(entries), cwpMaxRegistryEntries)
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, WireMagic)
	binary.Write(&buf, binary.LittleEndian, WireVersion)
	binary.Write(&buf, binary.LittleEndian, KBWireMsgCWPWorkloads)
	binary.Write(&buf, binary.LittleEndian, uint32(len(entries)))

	for _, e := range entries {
		var key [cwpWorkloadKeySize]byte
		copy(key[:], e.Path)
		buf.Write(key[:])
		buf.WriteByte(e.IdentityTier)
		buf.Write(e.ExpectedHash[:])
	}

	payloadBytes := buf.Bytes()
	payloadLen := uint32(len(payloadBytes))
	if int(payloadLen) != 8+len(entries)*cwpWorkloadEntrySize {
		return fmt.Errorf("ipc: internal error building CWP workloads frame: got %d bytes, want %d", payloadLen, 8+len(entries)*cwpWorkloadEntrySize)
	}

	var prefixBuf [4]byte
	binary.LittleEndian.PutUint32(prefixBuf[:], payloadLen)

	if _, err := conn.Write(prefixBuf[:]); err != nil {
		return fmt.Errorf("write prefix: %w", err)
	}
	if _, err := conn.Write(payloadBytes); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	log.Printf("[IPC] Sent %d protected workload(s) to kbd_sensor", len(entries))
	return nil
}
