package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestHostKeyLoadAndPersist(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kb_ssh_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "ssh_host_ed25519_key")

	// 1. Ensure key is generated when absent
	err = EnsureHostKeyExists(keyPath)
	if err != nil {
		t.Fatalf("EnsureHostKeyExists failed: %v", err)
	}

	// Verify key file exists
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("host key file was not created: %v", err)
	}

	// Read first generation key content
	content1, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	// 2. Ensure key is loaded and not regenerated when present
	err = EnsureHostKeyExists(keyPath)
	if err != nil {
		t.Fatalf("EnsureHostKeyExists failed on second run: %v", err)
	}

	content2, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file on second run: %v", err)
	}

	if string(content1) != string(content2) {
		t.Error("host key was regenerated when it should have been persisted")
	}
}

func TestAuthorizedKeysParsingAndValidation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kb_ssh_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	authPath := filepath.Join(tmpDir, "authorized_keys")

	// Generate a valid key pair for testing
	pubKey1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	sshPubKey1, err := gossh.NewPublicKey(pubKey1)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}

	// Generate another valid key pair
	pubKey2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	sshPubKey2, err := gossh.NewPublicKey(pubKey2)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}

	// Form authorized_keys string with comment and blank lines
	authorizedKeysContent := []byte(
		"# This is a comment\n" +
		string(gossh.MarshalAuthorizedKey(sshPubKey1)) + "\n" +
		"\n" +
		"# Another comment\n" +
		"  \n",
	)

	err = os.WriteFile(authPath, authorizedKeysContent, 0600)
	if err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	// Test authorized key passes validation
	if !ValidatePublicKey(authPath, sshPubKey1) {
		t.Error("expected valid public key to be accepted, but it was rejected")
	}

	// Test unauthorized key fails validation
	if ValidatePublicKey(authPath, sshPubKey2) {
		t.Error("expected unauthorized public key to be rejected, but it was accepted")
	}
}
