package main

// Signing support for CWP.md §4.3/§11.4's local-signed-policy model.
// kbctl is a separate Go module from kb-control-plane (see go.mod's
// `replace`), and Go's internal-package visibility rule blocks importing
// kb-control-plane/internal/ipc from here regardless — so the YAML
// shape and signing-payload construction below are intentionally kept as
// a small, self-contained mirror of kb-control-plane/internal/ipc/cwp.go's
// cwpWorkloadsYAML/CWPPolicyMetadata/buildSigningPayload. Keep these two
// in sync if either side's schema changes — same convention this repo
// already uses for wire-struct mirrors (e.g. internal/ipc/types.go's
// ContainmentCmdMsg comment).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type cwpWorkloadYAML struct {
	Path          string `yaml:"path"`
	IdentityTier  string `yaml:"identity_tier,omitempty"`
	ExpectedHash  string `yaml:"expected_hash,omitempty"`
	OwnerTeam     string `yaml:"owner_team,omitempty"`
	Justification string `yaml:"justification,omitempty"`
}

type cwpPolicyMetadata struct {
	Version        int    `yaml:"version,omitempty" json:"version"`
	SignedBy       string `yaml:"signed_by,omitempty" json:"signed_by"`
	RevocationMode string `yaml:"revocation_mode,omitempty" json:"revocation_mode"`
	Signature      string `yaml:"signature,omitempty" json:"-"`
}

type cwpWorkloadsYAML struct {
	CriticalWorkloads []cwpWorkloadYAML `yaml:"critical_workloads"`
	PolicyMetadata    cwpPolicyMetadata `yaml:"policy_metadata"`
}

type cwpSigningPayload struct {
	CriticalWorkloads []cwpWorkloadYAML `json:"critical_workloads"`
	Version           int               `json:"version"`
	SignedBy          string            `json:"signed_by"`
	RevocationMode    string            `json:"revocation_mode"`
}

func buildSigningPayload(doc cwpWorkloadsYAML) ([]byte, error) {
	return json.Marshal(cwpSigningPayload{
		CriticalWorkloads: doc.CriticalWorkloads,
		Version:           doc.PolicyMetadata.Version,
		SignedBy:          doc.PolicyMetadata.SignedBy,
		RevocationMode:    doc.PolicyMetadata.RevocationMode,
	})
}

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

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
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

var (
	workloadSignKeyPath    string
	workloadSignSignedBy   string
	workloadSignVersion    int
	workloadKeygenOutDir   string
	workloadKeygenBaseName string
)

var workloadSignCmd = &cobra.Command{
	Use:   "sign <workloads.yaml>",
	Short: "Sign a workloads.yaml file for kbd's --workloads-pubkey verification (CWP.md §4.3/§11.4)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if workloadSignKeyPath == "" {
			return fmt.Errorf("--key is required (path to an Ed25519 private key, see 'kbctl workload keygen')")
		}
		priv, err := loadEd25519PrivateKey(workloadSignKeyPath)
		if err != nil {
			return err
		}

		path := args[0]
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var doc cwpWorkloadsYAML
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("unmarshal %s: %w", path, err)
		}
		doc.PolicyMetadata.SignedBy = workloadSignSignedBy
		doc.PolicyMetadata.Version = workloadSignVersion
		doc.PolicyMetadata.Signature = ""

		payload, err := buildSigningPayload(doc)
		if err != nil {
			return fmt.Errorf("build signing payload: %w", err)
		}
		doc.PolicyMetadata.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

		out, err := yaml.Marshal(&doc)
		if err != nil {
			return fmt.Errorf("marshal signed %s: %w", path, err)
		}
		if err := os.WriteFile(path, out, 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Printf("Signed %s (signed_by=%q version=%d)\n", path, workloadSignSignedBy, workloadSignVersion)
		return nil
	},
}

var workloadKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 keypair for signing/verifying workloads.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate keypair: %w", err)
		}
		privPath := workloadKeygenOutDir + "/" + workloadKeygenBaseName + ".key"
		pubPath := workloadKeygenOutDir + "/" + workloadKeygenBaseName + ".pub"

		if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv.Seed())), 0600); err != nil {
			return fmt.Errorf("write %s: %w", privPath, err)
		}
		if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0644); err != nil {
			return fmt.Errorf("write %s: %w", pubPath, err)
		}
		fmt.Printf("Wrote private key (keep secret): %s\n", privPath)
		fmt.Printf("Wrote public key (for kbd's --workloads-pubkey): %s\n", pubPath)
		return nil
	},
}

func init() {
	workloadSignCmd.Flags().StringVar(&workloadSignKeyPath, "key", "", "path to the Ed25519 private key to sign with (required)")
	workloadSignCmd.Flags().StringVar(&workloadSignSignedBy, "signed-by", "", "identity recorded in policy_metadata.signed_by (CWP.md §12.1)")
	workloadSignCmd.Flags().IntVar(&workloadSignVersion, "version", 1, "policy_metadata.version to record")

	workloadKeygenCmd.Flags().StringVar(&workloadKeygenOutDir, "out-dir", ".", "directory to write the generated key pair into")
	workloadKeygenCmd.Flags().StringVar(&workloadKeygenBaseName, "name", "workloads-signer", "base filename for the generated <name>.key/<name>.pub")

	workloadCmd.AddCommand(workloadSignCmd)
	workloadCmd.AddCommand(workloadKeygenCmd)
}
