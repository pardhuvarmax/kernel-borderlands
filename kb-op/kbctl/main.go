package main

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// socketPath is the UDS kbd binds its gRPC server on (internal/ipc.SocketGRPC
// in kb-control-plane). All KernelBorderlands RPCs — including the ones
// kbctl calls — are multiplexed over this single socket; there is no
// separate TCP listener.
var socketPath string

var rootCmd = &cobra.Command{
	Use:   "kbctl",
	Short: "Kernel Borderlands control plane CLI",
	Long: `kbctl is the command-line control utility for Kernel Borderlands.
It talks to the kbd control plane daemon over gRPC on its Unix domain
socket (default /run/kb/kba.sock).`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "/run/kb/kba.sock",
		"path to kbd's gRPC Unix domain socket")

	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(zoneCmd)
	rootCmd.AddCommand(processCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(statsCmd)
}

// dial connects to kbd over its UDS gRPC socket. Every subcommand calls
// this rather than dialing independently, so the --socket flag and
// timeout behavior stay consistent across the whole CLI.
func dial() (*grpc.ClientConn, pb.KernelBorderlandsClient, error) {
	target := fmt.Sprintf("unix://%s", socketPath)
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", target, err)
	}
	return conn, pb.NewKernelBorderlandsClient(conn), nil
}

func withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
