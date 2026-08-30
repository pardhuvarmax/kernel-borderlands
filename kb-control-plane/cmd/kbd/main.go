package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/controlplane"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	"github.com/spf13/cobra"
)

var (
	dbPath        string
	policyPath    string
	rulesPath     string
	workloadsPath string
	httpAddr      string
	grpcSocket    string
)

var rootCmd = &cobra.Command{
	Use:   "kbd",
	Short: "Kernel Borderlands Control Plane Daemon",
	Long: `kbd is the control plane daemon for Kernel Borderlands.
It aggregates eBPF events, manages process behavioral state,
and coordinates with the AADS agent swarm.`,
	Run: runDaemon,
}

func init() {
	rootCmd.Flags().StringVarP(&dbPath, "db", "d", "/var/lib/kbd/state.db",
		"path to SQLite state database (L2 durable store)")
	rootCmd.Flags().StringVarP(&policyPath, "policy", "p", "config/policy.yaml",
		"path to policy.yaml (per-process thresholds, auto-terminate rules)")
	rootCmd.Flags().StringVar(&rulesPath, "rules", "config/rules.yaml",
		"path to rules.yaml (dynamic attack-chain rules pushed to the sensor at connect time); empty disables the push, sensor falls back to compiled-in default rules")
	rootCmd.Flags().StringVar(&workloadsPath, "workloads", "config/workloads.yaml",
		"path to workloads.yaml (CWP protected-workload registry, docs/features/CWP.md); empty disables CWP entirely. A missing file is not an error — CWP just has nothing registered")

	// §2.7: --http-addr/--grpc-socket now get real --help text and cobra
	// flags, matching --db/--policy above, instead of requiring an operator
	// to already know KB_HTTP_BIND/KB_GRPC_SOCKET exist. The env vars still
	// work — they set the flag's default, so an unset flag still respects
	// them, and a shell-exported env var keeps behaving exactly as before
	// for anyone with existing deployment scripts.
	defaultHTTPAddr := os.Getenv("KB_HTTP_BIND")
	if defaultHTTPAddr == "" {
		defaultHTTPAddr = "127.0.0.1:8080"
	}
	defaultGRPCSocket := os.Getenv("KB_GRPC_SOCKET")
	if defaultGRPCSocket == "" {
		defaultGRPCSocket = ipc.SocketGRPC
	}
	rootCmd.Flags().StringVar(&httpAddr, "http-addr", defaultHTTPAddr,
		"address for the HTTP API/SSE server (web dashboard) to bind — loopback-only by default")
	rootCmd.Flags().StringVar(&grpcSocket, "grpc-socket", defaultGRPCSocket,
		"path to the gRPC UDS socket (kba.sock)")
}

func runDaemon(cmd *cobra.Command, args []string) {
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║   Kernel Borderlands Control Plane       ║")
	fmt.Println("║   kbd v0.1.0                              ║")
	fmt.Println("╚══════════════════════════════════════════╝")

	cp, err := controlplane.New(dbPath, policyPath, rulesPath, workloadsPath)
	if err != nil {
		log.Fatalf("Failed to initialize control plane: %v", err)
	}

	if err := cp.Start(httpAddr, grpcSocket); err != nil {
		log.Fatalf("Failed to start control plane: %v", err)
	}

	// Wait for shutdown signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down KB Control Plane...")
	cp.Stop(grpcSocket)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}