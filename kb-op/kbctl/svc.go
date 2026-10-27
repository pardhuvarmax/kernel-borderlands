package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Unit names installed by the .deb / Arch packages (packaging/systemd/).
const (
	unitDashboard = "kbopd.service"
	unitSSH       = "sshd@kb-operator.service"
)

// stackUnits is the boot order from docs/architecture/boot_sequence_spec.md:
// kbd first (binds the sockets), then the sensor, then the watchdog, then
// the operator surfaces. `kbctl down` walks it in reverse.
var stackUnits = []string{
	"kbd.service",
	"kb-sensor.service",
	unitDashboard,
	unitSSH,
}

// maintenanceUnits are deliberately kept down. kb-checker is out of service
// for maintenance and repairs: `kbctl up` never starts it, `kbctl status`
// labels it, and kb-checker.service itself refuses to start unless
// /etc/kb/checker.enabled exists (ConditionPathExists in the unit).
var maintenanceUnits = []string{"kb-checker.service"}

const maintenanceLabel = "UNDER MAINTENANCE AND REPAIRS (kept down)"

// privileged runs name with args, prefixing sudo when not already root so
// `kbctl dashboard up` works from an operator's own shell.
func privileged(name string, args ...string) error {
	if os.Geteuid() != 0 {
		if sudo, err := exec.LookPath("sudo"); err == nil {
			args = append([]string{name}, args...)
			name = sudo
		}
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func systemctl(args ...string) error { return privileged("systemctl", args...) }

// unitState returns systemd's is-active answer ("active", "inactive",
// "failed", ...). is-active needs no privileges.
func unitState(unit string) string {
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	return "unknown"
}

func portOpen(host string, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// waitForPort polls until host:port accepts connections or timeout elapses.
func waitForPort(host string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if portOpen(host, port) {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("%s:%d not accepting connections after %s", host, port, timeout)
}

// findBinary resolves a sibling install (same dir as kbctl) before PATH, so
// a package install and a `make install` into /usr/local both work.
func findBinary(name string) (string, error) {
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), name); isExecutable(p) {
			return p, nil
		}
	}
	return exec.LookPath(name)
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}
