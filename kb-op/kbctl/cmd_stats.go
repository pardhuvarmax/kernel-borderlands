package main

import (
	"fmt"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Fetch global telemetry volumes and active process counts",
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, client, err := dial()
		if err != nil {
			return err
		}
		defer conn.Close()

		ctx, cancel := withTimeout()
		defer cancel()

		resp, err := client.GetSystemStats(ctx, &pb.Empty{})
		if err != nil {
			return err
		}

		fmt.Printf("events/sec:       %.2f\n", resp.EventsPerSecond)
		fmt.Printf("active processes: %d\n", resp.ActiveProcesses)
		return nil
	},
}
