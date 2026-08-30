package main

import (
	"fmt"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/spf13/cobra"
)

var workloadCmd = &cobra.Command{
	Use:   "workload",
	Short: "Manage kbd's CWP protected-workload registry (docs/features/CWP.md)",
}

var workloadReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload workloads.yaml and push the registry live to every connected sensor",
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, client, err := dial()
		if err != nil {
			return err
		}
		defer conn.Close()

		ctx, cancel := withTimeout()
		defer cancel()

		resp, err := client.ReloadWorkloads(ctx, &pb.Empty{})
		if err != nil {
			return err
		}
		if !resp.Success {
			return fmt.Errorf("workload reload failed: %s", resp.Message)
		}
		fmt.Println(resp.Message)
		return nil
	},
}

func init() {
	workloadCmd.AddCommand(workloadReloadCmd)
}
