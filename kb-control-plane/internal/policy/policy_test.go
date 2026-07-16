package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestPolicy(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
	return path
}

func TestNewWithNoPathUsesDefaults(t *testing.T) {
	e, err := New("")
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if e.AutoTerminate("anything") {
		t.Error("AutoTerminate should default to false for unknown comm")
	}
}

func TestNewWithMissingFileFallsBackToDefaults(t *testing.T) {
	e, err := New("/nonexistent/path/policy.yaml")
	if err != nil {
		t.Fatalf("New(missing file) should not error, got: %v", err)
	}
	if e.AutoTerminate("x") {
		t.Error("AutoTerminate should default to false when policy file is missing")
	}
}

func TestNewWithMalformedYAMLErrors(t *testing.T) {
	path := writeTestPolicy(t, "not: valid: yaml: [[[")
	if _, err := New(path); err == nil {
		t.Error("expected error for malformed YAML, got nil")
	}
}

func TestPerCommAutoTerminate(t *testing.T) {
	path := writeTestPolicy(t, `
defaults:
  suspicious: 40.0
  borderlands: 75.0

policies:
  - comm: postgres
    suspicious: 50.0
    borderlands: 80.0
    allow_network: false
    auto_terminate: true

  - comm: nginx
    suspicious: 55.0
    borderlands: 85.0
    auto_terminate: false
`)
	e, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !e.AutoTerminate("postgres") {
		t.Error("postgres AutoTerminate should be true")
	}
	if e.AutoTerminate("nginx") {
		t.Error("nginx AutoTerminate should be false")
	}
	if e.AutoTerminate("unlisted-proc") {
		t.Error("unlisted comm AutoTerminate should default to false")
	}
}

func TestSensitivePathsValid(t *testing.T) {
	path := writeTestPolicy(t, `
sensitive_paths:
  - /etc/kb-secrets
  - /var/lib/kb/keys/
  - /etc/shadow
  - /etc/kb-secrets
`)
	e, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := e.SensitivePaths()
	want := []string{"/etc/kb-secrets", "/var/lib/kb/keys/"}
	if len(got) != len(want) {
		t.Fatalf("SensitivePaths() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SensitivePaths()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSensitivePathsEmptyDefault(t *testing.T) {
	e, err := New(writeTestPolicy(t, "policies: []"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(e.SensitivePaths()) != 0 {
		t.Errorf("SensitivePaths() should be empty by default, got %v", e.SensitivePaths())
	}
}

func TestSensitivePathsRejectsBareRoot(t *testing.T) {
	e, err := New(writeTestPolicy(t, "sensitive_paths: [\"/\"]"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(e.SensitivePaths()) != 0 {
		t.Error("bare \"/\" should be rejected, falling back to empty (floor-only)")
	}
}

func TestSensitivePathsRejectsRelativePath(t *testing.T) {
	e, err := New(writeTestPolicy(t, "sensitive_paths: [\"etc/shadow\"]"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(e.SensitivePaths()) != 0 {
		t.Error("relative path should be rejected, falling back to empty (floor-only)")
	}
}

func TestSensitivePathsRejectsOversizedEntry(t *testing.T) {
	long := "/" + strings.Repeat("a", 63) // 64 bytes total, exceeds the 63-byte limit
	e, err := New(writeTestPolicy(t, "sensitive_paths: [\""+long+"\"]"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(e.SensitivePaths()) != 0 {
		t.Errorf("64-byte path should exceed the 63-byte key limit and be rejected, got %v", e.SensitivePaths())
	}
}

func TestSensitivePathsRejectsTooManyEntries(t *testing.T) {
	yamlLines := "sensitive_paths:\n"
	for i := 0; i < sensitivePathMapCapacity; i++ { // more than the 61 slots available beyond the 3-entry floor
		yamlLines += fmt.Sprintf("  - /custom/path-%d\n", i)
	}
	e, err := New(writeTestPolicy(t, yamlLines))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(e.SensitivePaths()) != 0 {
		t.Errorf("oversized list should be rejected wholesale, got %d entries", len(e.SensitivePaths()))
	}
}
