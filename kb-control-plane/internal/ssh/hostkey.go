package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// EnsureHostKeyExists verifies if a host key exists at the given path, and generates one if it doesn't.
func EnsureHostKeyExists(path string) error {
	if _, err := os.Stat(path); err == nil {
		// Key already exists
		return nil
	}

	// Create directory if not exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for host key %s: %w", dir, err)
	}

	// Generate ed25519 private key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 private key: %w", err)
	}

	// Marshal private key to PKCS#8
	bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal PKCS#8: %w", err)
	}

	// Encode to PEM
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}
	pemBytes := pem.EncodeToMemory(block)

	// Write to file with owner-only access (0600)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return fmt.Errorf("failed to write host key file %s: %w", path, err)
	}

	return nil
}
