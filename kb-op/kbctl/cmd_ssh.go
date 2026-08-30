package main

import (
	"fmt"
	"os"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/spf13/cobra"
)

// sshCmd's subcommands are the audit-tie-in callback described in
// docs/development/core-control/control-plane-catalog.md §2.12 step 5 —
// invoked by the ForceCommand wrapper script (docs/architecture/
// boot_sequence_spec.md §3), not run interactively by an operator. Kept
// under kbctl rather than a standalone binary so there's one less thing to
// build/install/version alongside kbd and kb-tui.
var sshCmd = &cobra.Command{
	Use:    "ssh",
	Short:  "SSH session audit callbacks (used by the ForceCommand wrapper script, not interactive)",
	Hidden: true,
}

var (
	sshPrincipal  string
	sshRemoteAddr string
	sshIdentity   string
)

func addSSHSessionFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&sshPrincipal, "principal", os.Getenv("USER"),
		"local user the SSH session landed as (defaults to $USER, which sshd sets for the ForceCommand child)")
	cmd.Flags().StringVar(&sshRemoteAddr, "remote-addr", os.Getenv("SSH_CONNECTION"),
		"client address (defaults to $SSH_CONNECTION, set by sshd)")
	cmd.Flags().StringVar(&sshIdentity, "identity", "",
		"key fingerprint or cert principal/serial identifying the credential used, if available")
}

func recordSSHSession(event string) error {
	conn, client, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := withTimeout()
	defer cancel()

	_, err = client.RecordSSHSession(ctx, &pb.SSHSessionEvent{
		Principal:  sshPrincipal,
		RemoteAddr: sshRemoteAddr,
		Identity:   sshIdentity,
		Event:      event,
	})
	return err
}

var sshSessionStartCmd = &cobra.Command{
	Use:   "session-start",
	Short: "Record an SSH session start in kbd's audit log",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := recordSSHSession("session_start"); err != nil {
			// Best-effort: an audit-logging failure must never block the
			// operator from actually reaching kb-tui — the wrapper script
			// runs this before exec'ing kb-tui, so a hard failure here
			// would turn an audit gap into a denial-of-access incident,
			// which is strictly worse. Print to stderr (visible in the
			// SSH session before the TUI takes over the screen) and exit 0.
			fmt.Fprintf(os.Stderr, "kbctl ssh session-start: audit logging failed (continuing anyway): %v\n", err)
		}
		return nil
	},
}

var sshSessionEndCmd = &cobra.Command{
	Use:   "session-end",
	Short: "Record an SSH session end in kbd's audit log",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := recordSSHSession("session_end"); err != nil {
			fmt.Fprintf(os.Stderr, "kbctl ssh session-end: audit logging failed: %v\n", err)
		}
		return nil
	},
}

func init() {
	addSSHSessionFlags(sshSessionStartCmd)
	addSSHSessionFlags(sshSessionEndCmd)
	sshCmd.AddCommand(sshSessionStartCmd)
	sshCmd.AddCommand(sshSessionEndCmd)
}
