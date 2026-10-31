package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAllowlist_MissingFileAndEmptyPathMeanNothingExempt(t *testing.T) {
	for _, p := range []string{"", filepath.Join(t.TempDir(), "nope.yaml")} {
		a, err := LoadAllowlist(p)
		if err != nil || a.Len() != 0 {
			t.Fatalf("path %q: want empty allowlist and no error, got %v / %d", p, err, a.Len())
		}
	}
}

func TestLoadAllowlist_ParsesEntriesAndRejectsBadOnes(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "a.yaml")
	os.WriteFile(good, []byte("allow:\n  - comm: systemd\n    reason: init\n  - comm: sshd\n    reason: remote access\n"), 0o644)
	a, err := LoadAllowlist(good)
	if err != nil || a.Len() != 2 {
		t.Fatalf("want 2 entries, got %v / %d", err, a.Len())
	}
	if e, ok := a.Match("systemd"); !ok || e.Reason != "init" || e.Path != "" {
		t.Errorf("systemd: %+v %v", e, ok)
	}
	if _, ok := a.Match("cat"); ok {
		t.Error("an unlisted comm must not match")
	}
	empty := filepath.Join(dir, "b.yaml")
	os.WriteFile(empty, []byte("allow:\n  - comm: \"\"\n"), 0o644)
	if _, err := LoadAllowlist(empty); err == nil {
		t.Error("an entry with an empty comm must be rejected")
	}
	bad := filepath.Join(dir, "c.yaml")
	os.WriteFile(bad, []byte("allow: [unclosed"), 0o644)
	if _, err := LoadAllowlist(bad); err == nil {
		t.Error("malformed YAML must be an error, not a silently empty allowlist")
	}
}

func TestLoadAllowlist_OptionalAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "a.yaml")
	os.WriteFile(ok, []byte("allow:\n  - comm: sshd\n    reason: r\n    path: /usr/sbin/sshd\n"), 0o644)
	a, err := LoadAllowlist(ok)
	if e, _ := a.Match("sshd"); err != nil || e.Path != "/usr/sbin/sshd" {
		t.Fatalf("path not kept: %v %+v", err, e)
	}
	bad := filepath.Join(dir, "b.yaml")
	os.WriteFile(bad, []byte("allow:\n  - comm: sshd\n    path: sbin/sshd\n"), 0o644)
	if _, err := LoadAllowlist(bad); err == nil {
		t.Error("a relative path must be rejected")
	}
}
