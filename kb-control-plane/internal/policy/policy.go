package policy

import (
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// sensitivePathFloor mirrors the compiled-in default list in
// kb-core/userspace/sensor/kbd_sensor.c's populate_sensitive_paths() —
// keep these two in sync. sensitive_paths in policy.yaml is additive on
// top of this floor and can never remove or replace it.
var sensitivePathFloor = []string{"/etc/shadow", "/etc/sudoers", "/root/.ssh/"}

// sensitivePathMaxKeyLen matches the fixed-size BPF map key
// (char[64] in kb-core/ebpf/kbd_sensor.bpf.c) minus one byte for the
// NUL terminator.
const sensitivePathMaxKeyLen = 63

// sensitivePathMapCapacity matches kb_sensitive_paths' max_entries in
// kb-core/ebpf/kbd_sensor.bpf.c. Operator-supplied entries share this
// capacity with the compiled-in floor.
const sensitivePathMapCapacity = 64

type ProcessPolicy struct {
	Comm              string  `yaml:"comm"`
	SuspiciousThresh  float64 `yaml:"suspicious"`
	BorderlandsThresh float64 `yaml:"borderlands"`
	AllowNetwork      bool    `yaml:"allow_network"`
	AutoTerminate     bool    `yaml:"auto_terminate"`
}

type PolicyFile struct {
	Defaults struct {
		Suspicious  float64 `yaml:"suspicious"`
		Borderlands float64 `yaml:"borderlands"`
	} `yaml:"defaults"`
	Policies       []ProcessPolicy `yaml:"policies"`
	SensitivePaths []string        `yaml:"sensitive_paths"`
}

// Engine only exposes what controlplane.go actually calls today
// (AutoTerminate). SuspiciousThreshold/BorderlandsThreshold were removed —
// zone classification now happens on the C side (kb_scoring.c) and arrives
// pre-computed in ProcessStateMsg.Zone; nothing on the Go side reads these
// per-comm thresholds anymore. defSus/defBor are parsed and kept only so
// loading a policy.yaml with defaults/thresholds in it doesn't silently
// ignore fields operators may still expect to configure — reintroduce the
// accessor methods if/when something on the Go side needs them again.
type Engine struct {
	byComm         map[string]ProcessPolicy
	defSus         float64
	defBor         float64
	sensitivePaths []string
}

func New(path string) (*Engine, error) {
	e := &Engine{byComm: make(map[string]ProcessPolicy), defSus: 40, defBor: 75}
	if path == "" {
		return e, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[Policy] no file at %s — defaults", path)
		return e, nil
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, err
	}
	if pf.Defaults.Suspicious > 0 {
		e.defSus = pf.Defaults.Suspicious
	}
	if pf.Defaults.Borderlands > 0 {
		e.defBor = pf.Defaults.Borderlands
	}
	for _, p := range pf.Policies {
		e.byComm[p.Comm] = p
	}
	log.Printf("[Policy] loaded %d process policies", len(pf.Policies))

	sp, err := validateSensitivePaths(pf.SensitivePaths)
	if err != nil {
		log.Printf("[Policy] sensitive_paths rejected, falling back to compiled-in floor only: %v", err)
	} else {
		e.sensitivePaths = sp
		if len(sp) > 0 {
			log.Printf("[Policy] loaded %d additional sensitive path(s)", len(sp))
		}
	}
	return e, nil
}

func (e *Engine) AutoTerminate(comm string) bool {
	if p, ok := e.byComm[comm]; ok {
		return p.AutoTerminate
	}
	return false
}

// SensitivePaths returns the validated, deduplicated operator-supplied
// additions to the LSM file-block list — never including the compiled-in
// floor itself (that stays hardcoded in kbd_sensor.c and is merged in on
// the C side). Empty if policy.yaml had none, or if validation rejected
// the list — in either case the compiled-in floor still applies on its
// own.
func (e *Engine) SensitivePaths() []string {
	return e.sensitivePaths
}

// validateSensitivePaths rejects the whole list on any single bad entry
// (rather than silently dropping just the offender) so a typo in
// policy.yaml can never partially, confusingly apply. Returns a
// deduplicated list with the compiled-in floor excluded.
func validateSensitivePaths(paths []string) ([]string, error) {
	floor := make(map[string]bool, len(sensitivePathFloor))
	for _, p := range sensitivePathFloor {
		floor[p] = true
	}

	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			return nil, fmt.Errorf("empty sensitive_paths entry")
		}
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("sensitive_paths entry %q must be an absolute path", p)
		}
		if p == "/" {
			return nil, fmt.Errorf("sensitive_paths entry \"/\" would block all file opens system-wide (LSM hook matches directory prefixes)")
		}
		if len(p) > sensitivePathMaxKeyLen {
			return nil, fmt.Errorf("sensitive_paths entry %q is %d bytes, exceeds the %d-byte fixed-size BPF map key", p, len(p), sensitivePathMaxKeyLen)
		}
		if floor[p] {
			continue // already protected by the compiled-in floor, silently skip
		}
		if seen[p] {
			continue // duplicate within the list, silently skip
		}
		seen[p] = true
		out = append(out, p)
	}

	if maxOperatorEntries := sensitivePathMapCapacity - len(sensitivePathFloor); len(out) > maxOperatorEntries {
		return nil, fmt.Errorf("sensitive_paths has %d entries after dedup, exceeds the %d slots available beyond the compiled-in floor (map capacity %d)", len(out), maxOperatorEntries, sensitivePathMapCapacity)
	}

	return out, nil
}
