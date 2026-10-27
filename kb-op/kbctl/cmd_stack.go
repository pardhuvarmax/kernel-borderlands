package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Enable and start the stack (kbd, sensor, dashboard, SSH console; kb-checker stays down for maintenance)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return systemctl(append([]string{"enable", "--now"}, stackUnits...)...)
	},
}

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop the whole stack in reverse boot order (does not disable it)",
	RunE: func(cmd *cobra.Command, args []string) error {
		for i := len(stackUnits) - 1; i >= 0; i-- {
			if err := systemctl("stop", stackUnits[i]); err != nil {
				return fmt.Errorf("stop %s: %w", stackUnits[i], err)
			}
		}
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the state of every Kernel Borderlands unit",
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, u := range stackUnits {
			fmt.Printf("%-28s %s\n", u, unitState(u))
		}
		for _, u := range maintenanceUnits {
			label := maintenanceLabel
			if unitState(u) == "active" {
				label = maintenanceActiveLabel
			}
			fmt.Printf("%-28s %s\n", u, label)
		}
		return nil
	},
}
