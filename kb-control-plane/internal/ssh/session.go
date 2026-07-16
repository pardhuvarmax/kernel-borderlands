package ssh

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/charmbracelet/ssh"
	"github.com/creack/pty"
	gossh "golang.org/x/crypto/ssh"
)

// handleSession handles the lifecycle of an incoming SSH session.
func handleSession(s ssh.Session) {
	remoteAddr := s.RemoteAddr().String()
	pubKey := s.PublicKey()
	var keyFingerprint string
	if pubKey != nil {
		keyFingerprint = gossh.FingerprintSHA256(pubKey)
	} else {
		keyFingerprint = "none"
	}
	log.Printf("[SSH] Session started from %s, key fingerprint: %s", remoteAddr, keyFingerprint)
	defer log.Printf("[SSH] Session ended from %s", remoteAddr)

	// Locate kb-tui binary
	tuiPath := os.Getenv("KB_TUI_PATH")
	if tuiPath == "" {
		// Try a few fallback paths
		paths := []string{
			"/home/emergence/Desktop/kernel-borderlands/kb-op/kb-tui/target/debug/kb-tui",
			"/home/emergence/Desktop/kernel-borderlands/kb-op/kb-tui/kb-tui",
			"kb-tui",
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				tuiPath = p
				break
			}
			if lp, err := exec.LookPath(p); err == nil {
				tuiPath = lp
				break
			}
		}
	}

	if tuiPath == "" {
		log.Printf("[SSH] Error: kb-tui binary not found")
		fmt.Fprintf(s, "Error: kb-tui binary not found on this system.\n")
		_ = s.Exit(1)
		return
	}

	cmd := exec.Command(tuiPath)

	// Forward environment variables
	cmd.Env = os.Environ()
	for _, env := range s.Environ() {
		cmd.Env = append(cmd.Env, env)
	}

	ptyReq, winCh, isPty := s.Pty()
	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}

	if !isPty {
		cmd.Stdin = s
		cmd.Stdout = s
		cmd.Stderr = s.Stderr()
		if err := cmd.Start(); err != nil {
			log.Printf("[SSH] Failed to start kb-tui: %v", err)
			fmt.Fprintf(s, "Error starting kb-tui: %v\n", err)
			_ = s.Exit(1)
			return
		}
		_ = cmd.Wait()
		_ = s.Exit(cmd.ProcessState.ExitCode())
		return
	}

	// Start command in a pty
	ptyFile, err := pty.Start(cmd)
	if err != nil {
		log.Printf("[SSH] Failed to start kb-tui with PTY: %v", err)
		fmt.Fprintf(s, "Error starting kb-tui with PTY: %v\n", err)
		_ = s.Exit(1)
		return
	}
	defer ptyFile.Close()

	// Monitor terminal resize events
	go func() {
		for win := range winCh {
			setWinsize(ptyFile, win.Width, win.Height)
		}
	}()

	// Apply initial window size
	setWinsize(ptyFile, ptyReq.Window.Width, ptyReq.Window.Height)

	// Copy SSH session input to TUI stdin
	go func() {
		_, _ = io.Copy(ptyFile, s)
	}()

	// Copy TUI stdout to SSH session output
	_, _ = io.Copy(s, ptyFile)

	// Wait for TUI process to exit
	_ = cmd.Wait()
	if cmd.ProcessState != nil {
		_ = s.Exit(cmd.ProcessState.ExitCode())
	} else {
		_ = s.Exit(0)
	}
}

// setWinsize updates the PTY terminal window size.
func setWinsize(f *os.File, w, h int) {
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ Row, Col, Xpixel, Ypixel uint16 }{
			Row: uint16(h),
			Col: uint16(w),
		})))
}
