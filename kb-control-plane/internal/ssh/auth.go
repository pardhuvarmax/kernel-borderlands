package ssh

import (
	"bytes"
	"log"
	"os"
	"strings"

	"github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// ValidatePublicKey reads the authorized keys file and returns true if the incoming key matches any entry.
func ValidatePublicKey(authKeysPath string, key ssh.PublicKey) bool {
	data, err := os.ReadFile(authKeysPath)
	if err != nil {
		log.Printf("[SSH] Failed to read authorized keys file %s: %v", authKeysPath, err)
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		authedKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		if bytes.Equal(key.Marshal(), authedKey.Marshal()) {
			return true
		}
	}

	return false
}
