package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Allowlist is the operator's list of comm names that are known, trusted, and
// have unusual-but-legitimate behaviour (init systems, package managers,
// remote-access daemons). It is loaded from allowlist.yaml.
//
// An entry never hides anything on its own: kbd (internal/controlplane/
// allowlist.go) honours a match only when the running process's REAL
// executable resolves under a trusted system directory, because comm is chosen
// by the process itself and a bare name match would let malware call itself
// "systemd". A honoured entry suppresses AUTOMATIC containment only; zone
// transitions are still recorded and reported, tagged allowlisted=<reason>, and
// an ALLOWLIST_EXEMPT audit entry is written whenever it applies.
type Allowlist struct {
	byComm map[string]string // comm -> reason
}

type allowlistFile struct {
	Allow []struct {
		Comm   string `yaml:"comm"`
		Reason string `yaml:"reason"`
	} `yaml:"allow"`
}

// LoadAllowlist reads allowlist.yaml. A missing or empty path is not an error:
// the allowlist is then empty (nothing exempt).
func LoadAllowlist(path string) (*Allowlist, error) {
	a := &Allowlist{byComm: map[string]string{}}
	if path == "" {
		return a, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return a, nil
		}
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	var f allowlistFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("allowlist: parse %s: %w", path, err)
	}
	for _, e := range f.Allow {
		c := strings.TrimSpace(e.Comm)
		if c == "" {
			return nil, fmt.Errorf("allowlist: entry with empty comm in %s", path)
		}
		a.byComm[c] = e.Reason
	}
	return a, nil
}

// Match reports whether comm is listed, and the operator's stated reason.
func (a *Allowlist) Match(comm string) (string, bool) {
	if a == nil {
		return "", false
	}
	r, ok := a.byComm[comm]
	return r, ok
}

// Len is the number of entries.
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.byComm)
}
