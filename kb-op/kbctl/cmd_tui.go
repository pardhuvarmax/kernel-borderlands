package main

import (
	"fmt"
	"syscall"

	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Run the terminal UI in this shell (same binary the SSH console serves)",
	Long: `Replaces this process with kbopd attached to your terminal, which renders the
ratatui console. For a remote session through the dedicated operator sshd
(port 2222) use 'kbctl ssh connect'.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := findBinary("kbopd")
		if err != nil {
			return fmt.Errorf("kbopd not found next to kbctl or in PATH: %w", err)
		}
		return syscall.Exec(path, []string{"kbopd"}, syscall.Environ())
	},
}
