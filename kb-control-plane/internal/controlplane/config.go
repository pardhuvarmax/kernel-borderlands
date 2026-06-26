package controlplane

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config mirrors config/kb.yaml (see config/README.md for the documented
// schema). Every field has a sane default via DefaultConfig so the daemon
// can start even before an operator has written a kb.yaml for this host.
type Config struct {
	GRPCPort    int               `yaml:"grpc_port"`
	Scoring     ScoringConfig     `yaml:"scoring"`
	Enforcement EnforcementConfig `yaml:"enforcement"`
	Audit       AuditConfig       `yaml:"audit"`
}

type ScoringConfig struct {
	Alpha      float64         `yaml:"alpha"`
	Thresholds ThresholdConfig `yaml:"thresholds"`
}

// ThresholdConfig defines the score boundaries for the Execution Zone Model
// (Table: Safe 0-39 / Suspicious 40-74 / Borderlands 75-100 by default).
type ThresholdConfig struct {
	Suspicious  float64 `yaml:"suspicious"`
	Borderlands float64 `yaml:"borderlands"`
}

type EnforcementConfig struct {
	// Mode is "permissive" (log only, no kernel-level action) or "enforcing".
	Mode string `yaml:"mode"`
}

type AuditConfig struct {
	Path       string `yaml:"path"`
	RemoteSIEM string `yaml:"remote_siem"`
}

// DefaultConfig returns the baseline configuration described in
// config/README.md.
func DefaultConfig() *Config {
	return &Config{
		GRPCPort: 50051,
		Scoring: ScoringConfig{
			Alpha: 0.3,
			Thresholds: ThresholdConfig{
				Suspicious:  40,
				Borderlands: 75,
			},
		},
		Enforcement: EnforcementConfig{Mode: "permissive"},
		Audit:       AuditConfig{Path: "/var/log/kb/audit.log"},
	}
}

// LoadConfig reads and parses a kb.yaml file. A missing file is not treated
// as an error — the daemon falls back to DefaultConfig() so a fresh checkout
// still runs out of the box. A malformed file IS an error, since silently
// ignoring bad policy/threshold config would be a security footgun.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}