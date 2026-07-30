package main

import (
	"fmt"
	"strings"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/spf13/cobra"
)

var processCmd = &cobra.Command{
	Use:   "process",
	Short: "Query or contain tracked processes",
}

var (
	isolatePid    uint32
	isolateLevel  string
	isolateReason string
)

var processIsolateCmd = &cobra.Command{
	Use:   "isolate",
	Short: "Forcefully contain/isolate a process",
	Long: `Sends a containment command to the kernel sensor via kbd's
SetContainment RPC. Defaults to NAMESPACE-level isolation; pass --level
to choose CGROUP, SECCOMP, NAMESPACE, or TERMINATE explicitly.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		levelName := strings.ToUpper(isolateLevel)
		levelVal, ok := pb.ContainmentLevel_value[levelName]
		if !ok {
			return fmt.Errorf("unknown containment level %q (want one of CGROUP, SECCOMP, NAMESPACE, TERMINATE)", isolateLevel)
		}

		conn, client, err := dial()
		if err != nil {
			return err
		}
		defer conn.Close()

		ctx, cancel := withTimeout()
		defer cancel()

		resp, err := client.SetContainment(ctx, &pb.ContainmentRequest{
			Pid:    isolatePid,
			Level:  pb.ContainmentLevel(levelVal),
			Reason: isolateReason,
		})
		if err != nil {
			return err
		}
		if !resp.Success {
			return fmt.Errorf("isolate failed")
		}
		fmt.Printf("pid=%d contained at level %s\n", isolatePid, levelName)
		return nil
	},
}

func init() {
	processIsolateCmd.Flags().Uint32Var(&isolatePid, "pid", 0, "target process PID (required)")
	processIsolateCmd.Flags().StringVar(&isolateLevel, "level", "NAMESPACE", "CGROUP | SECCOMP | NAMESPACE | TERMINATE")
	processIsolateCmd.Flags().StringVar(&isolateReason, "reason", "kbctl process isolate", "operator-supplied reason, recorded in the audit log")
	processIsolateCmd.MarkFlagRequired("pid")

	processCmd.AddCommand(processIsolateCmd)
}
