package policy

import (
	"os"
	"path/filepath"
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