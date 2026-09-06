package ipc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// decodeKeyMaterial accepts whatever format an operator's key tooling
// produced — hex, base64, or raw bytes — rather than requiring one
// specific encoding. Tried in that order; falls back to the raw file
// bytes if neither decode succeeds (the direct-raw-binary-file case).
func decodeKeyMaterial(raw []byte) []byte {
	s := strings.TrimSpace(string(raw))
	if b, err := hex.DecodeString(s); err == nil {
		return b
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	return raw
}

// LoadEd25519PublicKey reads an Ed25519 public key from path (raw 32-byte,
// hex, or base64 encoded) — used by kbd's --workloads-pubkey flag to
// verify CWP.md §4.3/§11.4 policy signatures.
func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}
	key := decodeKeyMaterial(raw)
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %s: got %d bytes, want %d", path, len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

// LoadEd25519PrivateKey reads an Ed25519 private key from path — a 32-byte
// seed (expanded via ed25519.NewKeyFromSeed) or a full 64-byte private
// key, hex/base64/raw encoded. Used by `kbctl workload sign`.
func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	key := decodeKeyMaterial(raw)
	switch len(key) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(key), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(key), nil
	default:
		return nil, fmt.Errorf("private key %s: got %d bytes, want %d (seed) or %d (full key)", path, len(key), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}
