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

// dashboardTokenURL adds the API token as a URL *fragment*: browsers never send the
// fragment to a server, and the dashboard moves it into sessionStorage and scrubs it
// from the address bar. Returns the plain URL if no token is readable.
func dashboardTokenURL() (string, bool) {
	if t := readAPIToken(); t != "" {
		return dashboardURL() + "/#token=" + t, true
	}
	return dashboardURL(), false
}

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

var dashboardURLWithToken bool

var dashboardURLCmd = &cobra.Command{
	Use:   "url",
	Short: "Print the dashboard URL (--token adds the API token fragment; treat the output as a secret)",
	Run: func(cmd *cobra.Command, args []string) {
		if dashboardURLWithToken {
			u, _ := dashboardTokenURL()
			fmt.Println(u)
			return
		}
		fmt.Println(dashboardURL())
	},
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
		target, haveToken := dashboardTokenURL()
		if !haveToken {
			fmt.Fprintf(os.Stderr, "note: no API token readable at %s; the dashboard will be read-only (isolate/restore/policy-reload fail closed)\n", apiEnvPath)
		}
		if err := exec.Command(opener, target).Start(); err != nil {
			fmt.Printf("could not launch a browser (%v); open %s manually (or: kbctl dashboard url --token)\n", err, dashboardURL())
			return nil
		}
		fmt.Println("opened", dashboardURL())
		return nil
	},
}

func init() {
	dashboardCmd.PersistentFlags().IntVar(&dashboardPort, "port", 8082,
		"dashboard port (kbopd's embedded server is fixed at 8082; change only if you rebuilt it)")
	dashboardURLCmd.Flags().BoolVar(&dashboardURLWithToken, "token", false, "include the API token as a URL fragment")
	dashboardCmd.AddCommand(dashboardUpCmd, dashboardDownCmd, dashboardStatusCmd, dashboardURLCmd, dashboardOpenCmd)
}
