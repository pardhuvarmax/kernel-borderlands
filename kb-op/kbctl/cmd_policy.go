package main

import (
	"fmt"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage kbd's dynamic policy configuration",
}

var policyReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload policy.yaml from the path kbd was started with",
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, client, err := dial()
		if err != nil {
			return err
		}
		defer conn.Close()

		ctx, cancel := withTimeout()
		defer cancel()

		resp, err := client.ReloadPolicy(ctx, &pb.Empty{})
		if err != nil {
			return err
		}
		if !resp.Success {
			return fmt.Errorf("policy reload failed: %s", resp.Message)
		}
		fmt.Println(resp.Message)
		return nil
	},
}

func init() {
	policyCmd.AddCommand(policyReloadCmd)
}
