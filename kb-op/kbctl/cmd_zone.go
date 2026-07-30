package main

import (
	"fmt"
	"strings"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/spf13/cobra"
)

var zoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Inspect or override process threat zone classification",
}

var (
	zoneOverridePid    uint32
	zoneOverrideZone   string
	zoneOverrideReason string
)

// zoneOverrideNamespaceCmd is registered as "kbctl zone override".
var zoneOverrideCmd = &cobra.Command{
	Use:   "override",
	Short: "Override a tracked process's zone classification",
	Long: `Relabels how kbd tracks a process's zone (SAFE / SUSPICIOUS /
BORDERLANDS) for display and classification purposes only — it does not
touch kernel or enforcement state. A subsequent real zone transition
event from the sensor will overwrite this the next time the process's
score crosses a threshold. The override is recorded in the audit log.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		zoneName := strings.ToUpper(zoneOverrideZone)
		zoneVal, ok := pb.Zone_value[zoneName]
		if !ok {
			return fmt.Errorf("unknown zone %q (want one of SAFE, SUSPICIOUS, BORDERLANDS)", zoneOverrideZone)
		}

		conn, client, err := dial()
		if err != nil {
			return err
		}
		defer conn.Close()

		ctx, cancel := withTimeout()
		defer cancel()

		resp, err := client.OverrideZone(ctx, &pb.ZoneOverrideRequest{
			Pid:    zoneOverridePid,
			Zone:   pb.Zone(zoneVal),
			Reason: zoneOverrideReason,
		})
		if err != nil {
			return err
		}
		if !resp.Success {
			return fmt.Errorf("zone override failed")
		}
		fmt.Printf("pid=%d zone overridden to %s\n", zoneOverridePid, zoneName)
		return nil
	},
}

func init() {
	zoneOverrideCmd.Flags().Uint32Var(&zoneOverridePid, "pid", 0, "target process PID (required)")
	zoneOverrideCmd.Flags().StringVar(&zoneOverrideZone, "zone", "", "SAFE | SUSPICIOUS | BORDERLANDS (required)")
	zoneOverrideCmd.Flags().StringVar(&zoneOverrideReason, "reason", "", "operator-supplied reason, recorded in the audit log")
	zoneOverrideCmd.MarkFlagRequired("pid")
	zoneOverrideCmd.MarkFlagRequired("zone")

	zoneCmd.AddCommand(zoneOverrideCmd)
}
