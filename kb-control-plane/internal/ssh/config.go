package ssh

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type Config struct {
	HostKeyPath        string
	AuthorizedKeysPath string
	BindAddr           string
	DevMode            bool
}

func LoadConfig() (*Config, error) {
	devMode := os.Getenv("KB_DEV") == "true" || flag.Lookup("test.v") != nil
	bindAddr := os.Getenv("KB_SSH_BIND")
	if bindAddr == "" {
		bindAddr = "0.0.0.0:2222"
	}

	prodHostKey := "/etc/kb/ssh_host_ed25519_key"
	prodAuthKeys := "/etc/kb/authorized_keys"

	etcKBDir := "/etc/kb"
	// Check if directory exists or can be created, and if it's writable.
	etcKBExists := true
	if _, err := os.Stat(etcKBDir); os.IsNotExist(err) {
		// Attempt to create it (might fail due to permissions, which is expected in dev without root)
		if err := os.MkdirAll(etcKBDir, 0755); err != nil {
			etcKBExists = false
		}
	}

	if !etcKBExists || !isDirWritable(etcKBDir) {
		if !devMode {
			return nil, fmt.Errorf("production mode error: directory %s is not accessible/writable and KB_DEV is not set to true", etcKBDir)
		}
		// Dev mode fallback
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get working directory: %w", err)
		}
		fallbackKey := filepath.Join(wd, "ssh_host_ed25519_key")
		fallbackAuth := filepath.Join(wd, "authorized_keys")
		log.Printf("=========================================================================")
		log.Printf("WARNING: Running in development mode with local SSH keys:")
		log.Printf("  Host Key:        %s", fallbackKey)
		log.Printf("  Authorized Keys: %s", fallbackAuth)
		log.Printf("=========================================================================")
		return &Config{
			HostKeyPath:        fallbackKey,
			AuthorizedKeysPath: fallbackAuth,
			BindAddr:           bindAddr,
			DevMode:            true,
		}, nil
	}

	return &Config{
		HostKeyPath:        prodHostKey,
		AuthorizedKeysPath: prodAuthKeys,
		BindAddr:           bindAddr,
		DevMode:            false,
	}, nil
}

func isDirWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return false
	}
	tmpFile, err := os.CreateTemp(path, "kb_write_test")
	if err != nil {
		return false
	}
	tmpFile.Close()
	os.Remove(tmpFile.Name())
	return true
}
