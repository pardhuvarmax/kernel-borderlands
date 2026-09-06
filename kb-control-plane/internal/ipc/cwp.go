package ipc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
// hash, plus PolicyID/OwnerTeam/Justification kept Go-side only for
// alert-escalation use (CWP.md §9, see internal/controlplane/severity.go)
// — the wire frame has no room for them (KB_CWP_WORKLOAD_ENTRY_SIZE is
// fixed-size, path+tier+hash only), so SendCWPWorkloads below still only
// ever encodes Path/IdentityTier/ExpectedHash to the sensor.
type CWPWorkloadEntry struct {
	Path          string
	IdentityTier  uint8 // cwpIdentityTierPath or cwpIdentityTierHash
	ExpectedHash  [sha256.Size]byte
	PolicyID      uint32 // 1-based, assigned in load order (CWP.md §6.2's policy_id)
	OwnerTeam     string
	Justification string
}

// cwpWorkloadYAML mirrors CWP.md §12.1's YAML schema. OwnerTeam/
// Justification are Go-side only, never sent over the wire (the C side
// has nowhere to put them — KB_CWP_WORKLOAD_ENTRY_SIZE is fixed-size,
// path+tier+hash only) — but ARE used Go-side for severity-escalated
// alerting (CWP.md §9, internal/controlplane/severity.go), not just
// logged for documentation value.
type cwpWorkloadYAML struct {
	Path          string `yaml:"path"`
	IdentityTier  string `yaml:"identity_tier"` // "path" or "hash"
	ExpectedHash  string `yaml:"expected_hash"` // hex-encoded SHA-256; optional for identity_tier=hash (see LoadWorkloadsYAML)
	OwnerTeam     string `yaml:"owner_team"`
	Justification string `yaml:"justification"`
}

// CWPPolicyMetadata mirrors CWP.md §12.1's policy_metadata block. Signature
// is a base64-encoded Ed25519 signature (§4.3/§11.4) over the canonical
// JSON payload built by cwpSigningPayload — everything in this struct
// EXCEPT Signature itself, plus CriticalWorkloads.
type CWPPolicyMetadata struct {
	Version        int    `yaml:"version,omitempty" json:"version"`
	SignedBy       string `yaml:"signed_by,omitempty" json:"signed_by"`
	RevocationMode string `yaml:"revocation_mode,omitempty" json:"revocation_mode"`
	Signature      string `yaml:"signature,omitempty" json:"-"`
}

type cwpWorkloadsYAML struct {
	CriticalWorkloads []cwpWorkloadYAML `yaml:"critical_workloads"`
	PolicyMetadata    CWPPolicyMetadata `yaml:"policy_metadata"`
}

// cwpSigningPayload is the exact content an Ed25519 signature covers.
// Deliberately a fixed-field struct (not a map) so json.Marshal's field
// order is deterministic — signing and verification both marshal through
// this same type, so they can never disagree on byte layout.
type cwpSigningPayload struct {
	CriticalWorkloads []cwpWorkloadYAML `json:"critical_workloads"`
	Version           int               `json:"version"`
	SignedBy          string            `json:"signed_by"`
	RevocationMode    string            `json:"revocation_mode"`
}

func buildSigningPayload(doc cwpWorkloadsYAML) ([]byte, error) {
	return json.Marshal(cwpSigningPayload{
		CriticalWorkloads: doc.CriticalWorkloads,
		Version:           doc.PolicyMetadata.Version,
		SignedBy:          doc.PolicyMetadata.SignedBy,
		RevocationMode:    doc.PolicyMetadata.RevocationMode,
	})
}

// VerifyWorkloadsSignature checks that workloads YAML content carries a
// valid Ed25519 signature (policy_metadata.signature, base64) over its
// critical_workloads + version/signed_by/revocation_mode content, per
// CWP.md §4.3 ("Per-Host Policy Cache (local file, signed)") and §11.4
// ("cluster-synchronized policy is signed... verified before being
// trusted"). Callers (controlplane.go) must reject the file entirely on
// any error and keep the last known-good registry — this function never
// returns a partially-trusted result. Note: this verifies a LOCAL file's
// signature; it does not implement §4.3's networked "Central Policy
// Store" push/pull — no such fleet-management server exists anywhere in
// this codebase for any subsystem, and inventing one (transport, auth,
// discovery) is a separate infrastructure decision, not part of this
// change. This closes the "local cache is signed and verified" half of
// §4.3, which is the concretely-specified, buildable part.
func VerifyWorkloadsSignature(data []byte, trustedPubKey ed25519.PublicKey) error {
	if len(trustedPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("verify workloads signature: invalid public key size %d (want %d)", len(trustedPubKey), ed25519.PublicKeySize)
	}
	var doc cwpWorkloadsYAML
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("verify workloads signature: unmarshal: %w", err)
	}
	if doc.PolicyMetadata.Signature == "" {
		return fmt.Errorf("verify workloads signature: policy_metadata.signature is missing — a trusted public key is configured, so unsigned policy is rejected (CWP.md §11.4)")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.PolicyMetadata.Signature)
	if err != nil {
		return fmt.Errorf("verify workloads signature: decode base64 signature: %w", err)
	}
	payload, err := buildSigningPayload(doc)
	if err != nil {
		return fmt.Errorf("verify workloads signature: build payload: %w", err)
	}
	if !ed25519.Verify(trustedPubKey, payload, sig) {
		return fmt.Errorf("verify workloads signature: signature mismatch — policy may have been tampered with, or was signed by a key other than the configured trusted key")
	}
	return nil
}

// SignWorkloadsFile reads a workloads YAML file, signs its
// critical_workloads + version/signed_by/revocation_mode content with
// priv, and writes the signature back into policy_metadata.signature in
// place. This is an operator/CI-side signing step (see `kbctl workload
// sign`, kb-op/kbctl/cmd_workload.go) — kbd itself only ever verifies,
// never signs.
func SignWorkloadsFile(path string, priv ed25519.PrivateKey, signedBy string, version int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("sign workloads file: read: %w", err)
	}
	var doc cwpWorkloadsYAML
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("sign workloads file: unmarshal: %w", err)
	}
	doc.PolicyMetadata.SignedBy = signedBy
	doc.PolicyMetadata.Version = version
	doc.PolicyMetadata.Signature = ""

	payload, err := buildSigningPayload(doc)
	if err != nil {
		return fmt.Errorf("sign workloads file: build payload: %w", err)
	}
	doc.PolicyMetadata.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("sign workloads file: marshal: %w", err)
	}
	if err := os.WriteFile(path, out, 0644); err != nil {
		return fmt.Errorf("sign workloads file: write: %w", err)
	}
	return nil
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

		entry := CWPWorkloadEntry{
			Path:          w.Path,
			PolicyID:      uint32(len(entries) + 1), // 1-based, load-order (CWP.md §6.2)
			OwnerTeam:     w.OwnerTeam,
			Justification: w.Justification,
		}

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
