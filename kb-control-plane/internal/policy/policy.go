package policy

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

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
	Policies []ProcessPolicy `yaml:"policies"`
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
	byComm map[string]ProcessPolicy
	defSus float64
	defBor float64
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
	return e, nil
}

func (e *Engine) AutoTerminate(comm string) bool {
	if p, ok := e.byComm[comm]; ok {
		return p.AutoTerminate
	}
	return false
}