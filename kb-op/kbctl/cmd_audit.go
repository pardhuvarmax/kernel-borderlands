package main

import (
	"encoding/json"
	"fmt"
	"os"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect the SHA-256 hash-chained audit log",
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the audit log hash chain has not been tampered with",
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, client, err := dial()
		if err != nil {
			return err
		}
		defer conn.Close()

		ctx, cancel := withTimeout()
		defer cancel()

		resp, err := client.VerifyAuditChain(ctx, &pb.Empty{})
		if err != nil {
			return err
		}

		if resp.ChainIntact {
			fmt.Printf("chain intact — %d entries verified\n", resp.EntriesVerified)
			return nil
		}

		fmt.Printf("CHAIN BROKEN — %d entries verified before break\n", resp.EntriesVerified)
		if resp.Error != "" {
			fmt.Println(resp.Error)
		}
		os.Exit(1)
		return nil
	},
}

var auditExportOut string

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the full hash-chained audit log as JSON",
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, client, err := dial()
		if err != nil {
			return err
		}
		defer conn.Close()

		ctx, cancel := withTimeout()
		defer cancel()

		resp, err := client.ExportAuditLog(ctx, &pb.Empty{})
		if err != nil {
			return err
		}

		payload, err := json.MarshalIndent(resp.Entries, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal audit export: %w", err)
		}

		if auditExportOut == "" || auditExportOut == "-" {
			fmt.Println(string(payload))
			return nil
		}
		if err := os.WriteFile(auditExportOut, payload, 0o640); err != nil {
			return fmt.Errorf("write %s: %w", auditExportOut, err)
		}
		fmt.Printf("wrote %d entries to %s\n", len(resp.Entries), auditExportOut)
		return nil
	},
}

func init() {
	auditExportCmd.Flags().StringVar(&auditExportOut, "out", "", "output file (JSON); defaults to stdout")

	auditCmd.AddCommand(auditVerifyCmd)
	auditCmd.AddCommand(auditExportCmd)
}
