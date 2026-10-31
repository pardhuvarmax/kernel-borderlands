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
	byComm map[string]AllowEntry // comm -> entry
}

// AllowEntry is one allowlist entry. Path is optional: when set, the process's
// real executable must equal it exactly (the strongest form).
type AllowEntry struct {
	Reason string
	Path   string
}

type allowlistFile struct {
	Allow []struct {
		Comm   string `yaml:"comm"`
		Reason string `yaml:"reason"`
		Path   string `yaml:"path"`
	} `yaml:"allow"`
}

// LoadAllowlist reads allowlist.yaml. A missing or empty path is not an error:
// the allowlist is then empty (nothing exempt).
func LoadAllowlist(path string) (*Allowlist, error) {
	a := &Allowlist{byComm: map[string]AllowEntry{}}
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
		if e.Path != "" && !strings.HasPrefix(e.Path, "/") {
			return nil, fmt.Errorf("allowlist: path %q for %s must be absolute", e.Path, c)
		}
		a.byComm[c] = AllowEntry{Reason: e.Reason, Path: e.Path}
	}
	return a, nil
}

// Match reports whether comm is listed, with its entry.
func (a *Allowlist) Match(comm string) (AllowEntry, bool) {
	if a == nil {
		return AllowEntry{}, false
	}
	e, ok := a.byComm[comm]
	return e, ok
}

// Len is the number of entries.
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.byComm)
}
