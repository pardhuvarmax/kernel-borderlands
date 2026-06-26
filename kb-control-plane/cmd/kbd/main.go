package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kb-research/kb-control-plane/internal/controlplane"
	"github.com/spf13/cobra"
)

var configPath string

var rootCmd = &cobra.Command{
	Use:   "kbd",
	Short: "Kernel Borderlands Control Plane Daemon",
	Long: `kbd is the control plane daemon for Kernel Borderlands.
It aggregates eBPF events, manages process behavioral state,
and coordinates with the AADS agent swarm.`,
	Run: runDaemon,
}

func init() {
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "config/kb.yaml",
		"path to kb.yaml config file")
}

func runDaemon(cmd *cobra.Command, args []string) {
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║   Kernel Borderlands Control Plane       ║")
	fmt.Println("║   kbd v0.1.0                              ║")
	fmt.Println("╚══════════════════════════════════════════╝")

	cp, err := controlplane.New(configPath)
	if err != nil {
		log.Fatalf("Failed to initialize control plane: %v", err)
	}

	if err := cp.Start(); err != nil {
		log.Fatalf("Failed to start control plane: %v", err)
	}

	// Wait for shutdown signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down KB Control Plane...")
	cp.Stop()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}