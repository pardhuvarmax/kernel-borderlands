package ipc

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// --- LoadWorkloadsYAML ---

func TestLoadWorkloadsYAML_PathTierDefault(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "workloads.yaml", `
critical_workloads:
  - path: /usr/bin/postgres
    owner_team: data-platform
    justification: "test"
`)
	entries, err := LoadWorkloadsYAML(path)
	if err != nil {
		t.Fatalf("LoadWorkloadsYAML: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Path != "/usr/bin/postgres" {
		t.Errorf("got path=%q, want /usr/bin/postgres", entries[0].Path)
	}
	if entries[0].IdentityTier != cwpIdentityTierPath {
		t.Errorf("got identity_tier=%d, want path-tier (%d) when unspecified", entries[0].IdentityTier, cwpIdentityTierPath)
	}
}

func TestLoadWorkloadsYAML_HashTierWithExplicitHash(t *testing.T) {
	dir := t.TempDir()
	hash := sha256.Sum256([]byte("fake binary contents"))
	path := writeTempFile(t, dir, "workloads.yaml", `
critical_workloads:
  - path: /usr/bin/vault
    identity_tier: hash
    expected_hash: "`+hex.EncodeToString(hash[:])+`"
    owner_team: security-infra
    justification: "test"
`)
	entries, err := LoadWorkloadsYAML(path)
	if err != nil {
		t.Fatalf("LoadWorkloadsYAML: %v", err)
	}
	if entries[0].IdentityTier != cwpIdentityTierHash {
		t.Errorf("got identity_tier=%d, want hash-tier (%d)", entries[0].IdentityTier, cwpIdentityTierHash)
	}
	if entries[0].ExpectedHash != hash {
		t.Errorf("got hash=%x, want %x", entries[0].ExpectedHash, hash)
	}
}

func TestLoadWorkloadsYAML_HashTierComputedLocallyWhenOmitted(t *testing.T) {
	// A short, fixed-prefix path — t.TempDir()'s test-name-derived nesting
	// can exceed the 64-byte wire key on its own, which isn't what this
	// test is checking (that's TestLoadWorkloadsYAML_PathTooLongForWireKeyRejected).
	dir, err := os.MkdirTemp("", "kbcwp")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	binContents := "fake binary contents for local hashing"
	binPath := writeTempFile(t, dir, "bin", binContents)
	yamlPath := writeTempFile(t, dir, "workloads.yaml", `
critical_workloads:
  - path: `+binPath+`
    identity_tier: hash
`)
	entries, err := LoadWorkloadsYAML(yamlPath)
	if err != nil {
		t.Fatalf("LoadWorkloadsYAML: %v", err)
	}
	want := sha256.Sum256([]byte(binContents))
	if entries[0].ExpectedHash != want {
		t.Errorf("got hash=%x, want locally-computed hash %x", entries[0].ExpectedHash, want)
	}
}

func TestLoadWorkloadsYAML_HashTierUnreadableFileErrors(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTempFile(t, dir, "workloads.yaml", `
critical_workloads:
  - path: /nonexistent/binary
    identity_tier: hash
`)
	_, err := LoadWorkloadsYAML(yamlPath)
	if err == nil {
		t.Fatal("expected error for hash-tier entry with unreadable file and no expected_hash override, got nil")
	}
}

func TestLoadWorkloadsYAML_InvalidIdentityTierRejected(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTempFile(t, dir, "workloads.yaml", `
critical_workloads:
  - path: /usr/bin/x
    identity_tier: bogus
`)
	_, err := LoadWorkloadsYAML(yamlPath)
	if err == nil {
		t.Fatal("expected error for invalid identity_tier, got nil")
	}
}

func TestLoadWorkloadsYAML_PathTooLongForWireKeyRejected(t *testing.T) {
	dir := t.TempDir()
	longPath := "/" + string(make([]byte, cwpWorkloadKeySize)) // definitely >= 64 bytes
	yamlPath := writeTempFile(t, dir, "workloads.yaml", "critical_workloads:\n  - path: \""+longPath+"\"\n")
	_, err := LoadWorkloadsYAML(yamlPath)
	if err == nil {
		t.Fatal("expected error for a path that doesn't fit the 64-byte wire key, got nil")
	}
}

func TestLoadWorkloadsYAML_TooManyEntriesRejected(t *testing.T) {
	dir := t.TempDir()
	yaml := "critical_workloads:\n"
	for i := 0; i < cwpMaxRegistryEntries+1; i++ {
		yaml += "  - path: /usr/bin/x" + string(rune('a'+i%26)) + "\n"
	}
	yamlPath := writeTempFile(t, dir, "workloads.yaml", yaml)
	_, err := LoadWorkloadsYAML(yamlPath)
	if err == nil {
		t.Fatal("expected error when entry count exceeds CWP_MAX_REGISTRY_ENTRIES, got nil")
	}
}

func TestLoadWorkloadsYAML_EmptyListOK(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTempFile(t, dir, "workloads.yaml", "critical_workloads: []\n")
	entries, err := LoadWorkloadsYAML(yamlPath)
	if err != nil {
		t.Fatalf("LoadWorkloadsYAML: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

// --- SendCWPWorkloads wire format ---

func TestSendCWPWorkloads_WireFormat(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	hash := sha256.Sum256([]byte("x"))
	entries := []CWPWorkloadEntry{
		{Path: "/usr/bin/postgres", IdentityTier: cwpIdentityTierPath},
		{Path: "/usr/bin/vault", IdentityTier: cwpIdentityTierHash, ExpectedHash: hash},
	}

	errCh := make(chan error, 1)
	go func() { errCh <- SendCWPWorkloads(serverConn, entries) }()

	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	wantLen := uint32(8 + len(entries)*cwpWorkloadEntrySize)
	if length != wantLen {
		t.Fatalf("length prefix = %d, want %d", length, wantLen)
	}

	buf := make([]byte, length)
	if _, err := readFull(clientConn, buf); err != nil {
		t.Fatalf("reading frame: %v", err)
	}

	if got := binary.LittleEndian.Uint16(buf[0:2]); got != WireMagic {
		t.Errorf("magic = %#x, want %#x", got, WireMagic)
	}
	if buf[2] != WireVersion {
		t.Errorf("version = %d, want %d", buf[2], WireVersion)
	}
	if buf[3] != KBWireMsgCWPWorkloads {
		t.Errorf("msg_type = %d, want %d", buf[3], KBWireMsgCWPWorkloads)
	}
	if got := binary.LittleEndian.Uint32(buf[4:8]); got != uint32(len(entries)) {
		t.Errorf("count = %d, want %d", got, len(entries))
	}

	// First entry: path-tier, path field null-padded to 64 bytes.
	e0 := buf[8 : 8+cwpWorkloadEntrySize]
	gotPath0 := string(e0[:len(entries[0].Path)])
	if gotPath0 != entries[0].Path {
		t.Errorf("entry 0 path = %q, want %q", gotPath0, entries[0].Path)
	}
	for _, b := range e0[len(entries[0].Path):cwpWorkloadKeySize] {
		if b != 0 {
			t.Fatalf("entry 0 path field not zero-padded past the string")
		}
	}
	if e0[cwpWorkloadKeySize] != cwpIdentityTierPath {
		t.Errorf("entry 0 identity_tier = %d, want path (%d)", e0[cwpWorkloadKeySize], cwpIdentityTierPath)
	}

	// Second entry: hash-tier, hash bytes present.
	e1 := buf[8+cwpWorkloadEntrySize : 8+2*cwpWorkloadEntrySize]
	if e1[cwpWorkloadKeySize] != cwpIdentityTierHash {
		t.Errorf("entry 1 identity_tier = %d, want hash (%d)", e1[cwpWorkloadKeySize], cwpIdentityTierHash)
	}
	gotHash := e1[cwpWorkloadKeySize+1 : cwpWorkloadKeySize+1+sha256.Size]
	if string(gotHash) != string(hash[:]) {
		t.Errorf("entry 1 hash = %x, want %x", gotHash, hash)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("SendCWPWorkloads returned error: %v", err)
	}
}

func TestSendCWPWorkloads_TooManyEntriesRejected(t *testing.T) {
	entries := make([]CWPWorkloadEntry, cwpMaxRegistryEntries+1)
	for i := range entries {
		entries[i] = CWPWorkloadEntry{Path: "/x"}
	}
	if err := SendCWPWorkloads(nil, entries); err == nil {
		t.Fatal("expected error for entry count exceeding CWP_MAX_REGISTRY_ENTRIES, got nil")
	}
}

// --- Connect-time + live broadcast wiring ---

func TestPushConnectTimeFrames_SendsCWPWorkloadsWhenConfigured(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	l := &Listener{conns: map[net.Conn]bool{}}
	l.SetCWPWorkloads([]CWPWorkloadEntry{{Path: "/usr/bin/postgres", IdentityTier: cwpIdentityTierPath}})

	go l.pushConnectTimeFrames(serverConn)

	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	buf := make([]byte, length)
	if _, err := readFull(clientConn, buf); err != nil {
		t.Fatalf("reading frame: %v", err)
	}
	if buf[3] != KBWireMsgCWPWorkloads {
		t.Errorf("msg_type = %d, want %d (CWP workloads) — with no rules/sensitive-paths configured this should be the only frame sent", buf[3], KBWireMsgCWPWorkloads)
	}
}

func TestBroadcastCWPWorkloads_NoConnectedSensorsErrors(t *testing.T) {
	l := &Listener{conns: map[net.Conn]bool{}}
	l.SetCWPWorkloads([]CWPWorkloadEntry{{Path: "/usr/bin/postgres"}})

	if err := l.BroadcastCWPWorkloads(); err == nil {
		t.Fatal("expected error when no sensors are connected, got nil")
	}
}

func TestBroadcastCWPWorkloads_NoWorkloadsConfiguredIsNoop(t *testing.T) {
	l := &Listener{conns: map[net.Conn]bool{}} // no workloads set, no conns either
	if err := l.BroadcastCWPWorkloads(); err != nil {
		t.Errorf("expected nil error when no workloads are configured (nothing to send), got %v", err)
	}
}
