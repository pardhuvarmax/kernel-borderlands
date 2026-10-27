package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

// dashboardPort mirrors the port hardcoded in kb-op/kb-tui/src/main.rs
// (the embedded dashboard server in kbopd binds 127.0.0.1:8082).
var dashboardPort int

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Start, stop and open the embedded web dashboard (kbopd.service)",
	Long: `Manage the web dashboard served by kbopd, the unified kb-tui binary that
embeds kb-dashboard's production build. It listens on 127.0.0.1 only; reach it
from another machine with an SSH local forward or use the SSH TUI
('kbctl ssh connect') instead.`,
}

func dashboardURL() string { return fmt.Sprintf("http://127.0.0.1:%d", dashboardPort) }

func ensureDashboardUp() error {
	if unitState(unitDashboard) != "active" {
		if err := systemctl("enable", "--now", unitDashboard); err != nil {
			return fmt.Errorf("start %s: %w", unitDashboard, err)
		}
	}
	return waitForPort("127.0.0.1", dashboardPort, 15*time.Second)
}

var dashboardUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Enable and start the web dashboard, then print its URL",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureDashboardUp(); err != nil {
			return err
		}
		fmt.Println("dashboard up:", dashboardURL())
		return nil
	},
}

var dashboardDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop and disable the web dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		return systemctl("disable", "--now", unitDashboard)
	},
}

var dashboardStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether the dashboard unit is running and its port is answering",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, listening := unitState(unitDashboard), portOpen("127.0.0.1", dashboardPort)
		fmt.Printf("%s: %s, %s listening=%v\n", unitDashboard, state, dashboardURL(), listening)
		if state != "active" || !listening {
			os.Exit(3)
		}
		return nil
	},
}

var dashboardURLCmd = &cobra.Command{
	Use:   "url",
	Short: "Print the dashboard URL",
	Run:   func(cmd *cobra.Command, args []string) { fmt.Println(dashboardURL()) },
}

var dashboardOpenCmd = &cobra.Command{
	Use:   "open",
	Short: "Start the dashboard if needed and open it in the default browser",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureDashboardUp(); err != nil {
			return err
		}
		opener := "xdg-open"
		if runtime.GOOS == "darwin" {
			opener = "open"
		}
		if err := exec.Command(opener, dashboardURL()).Start(); err != nil {
			fmt.Printf("could not launch a browser (%v); open %s manually\n", err, dashboardURL())
			return nil
		}
		fmt.Println("opened", dashboardURL())
		return nil
	},
}

func init() {
	dashboardCmd.PersistentFlags().IntVar(&dashboardPort, "port", 8082,
		"dashboard port (kbopd's embedded server is fixed at 8082; change only if you rebuilt it)")
	dashboardCmd.AddCommand(dashboardUpCmd, dashboardDownCmd, dashboardStatusCmd, dashboardURLCmd, dashboardOpenCmd)
}
