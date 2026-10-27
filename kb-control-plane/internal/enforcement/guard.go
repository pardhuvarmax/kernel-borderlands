package enforcement

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// Go-side CPM/CWP gate for TERMINATE (docs/features/CPM.md, CWP.md).
//
// The sensor already refuses to contain a protected process (cpm_classify /
// cwp_classify in kbd_sensor.c), but it does so silently: kbd learns nothing
// from it, and Contain returns success once the frame is written. A SIGKILL
// sent by kbd after that would get past both gates. So kbd applies the same
// rules itself, before sending level 4 and before killing, and fails closed
// when it cannot tell what a process is. The sensor-side gates stay in
// place as the second layer.
//
// What this mirrors: PID 1, kernel threads, the protected-executable list
// (CPM); path-tier and hash-tier workloads from the loaded registry (CWP).
// What it cannot see: the sensor's live protected_pids_map. Closing that
// fully needs the sensor to report its decision back to kbd.

// procRoot is a variable so tests can point the classifier at a fake /proc.
var procRoot = "/proc"

const (
	pfKthread = 0x00200000 // PF_KTHREAD in /proc/<pid>/stat flags
	// The sensor keys its path maps on 64-byte NUL-padded strings, so a path
	// is compared on its first 63 bytes. Matching the same way here means a
	// path the sensor protects is never missed; a long path that only shares
	// the 63-byte prefix is treated as protected too (fail closed).
	pathKeyLen = 63
)

// cpmProtectedExecPaths is the sensor's compiled-in protected-executable
// floor (populate_protected_exec_paths in kbd_sensor.c) plus the locations
// the packaged install uses (/usr/bin, /usr/sbin), which that list does not
// contain, and the CPM.md §5.2 sensor components.
var cpmProtectedExecPaths = []string{
	"/usr/lib/systemd/systemd",
	"/lib/systemd/systemd",
	"/usr/lib/systemd/systemd-logind",
	"/lib/systemd/systemd-logind",
	"/usr/lib/systemd/systemd-udevd",
	"/lib/systemd/systemd-udevd",
	"/usr/bin/dbus-daemon",
	"/usr/bin/NetworkManager",
	"/usr/sbin/NetworkManager",
	"/usr/local/bin/kb-checker",
	"/usr/local/bin/kbd",
	"/usr/local/bin/kbd_sensor",
	"/usr/local/bin/kbagents",
	"/usr/local/bin/kbopd",
	"/usr/local/bin/kbopt",
	"/usr/bin/kb-sensor",
	"/usr/bin/kb-checker",
	"/usr/bin/kbd",
	"/usr/bin/kbd_sensor",
	"/usr/bin/kbagents",
	"/usr/bin/kbopd",
	"/usr/bin/kbopt",
	"/usr/bin/kbctl",
	"/usr/sbin/kbctl",
	"/usr/sbin/kbd",
	"/usr/sbin/kbd_sensor",
}

// errProcessGone means the target no longer exists; there is nothing to
// contain or kill.
var errProcessGone = errors.New("process no longer exists")

// terminateTarget is a process pinned by a pidfd after it passed the gate.
type terminateTarget interface {
	// Kill delivers SIGKILL to exactly the process that was classified.
	Kill() error
	Close()
}

// prepareTerminate pins pid and checks it against CPM and CWP. It is a
// variable so tests never need a real target.
var prepareTerminate = realPrepareTerminate

func realPrepareTerminate(e *Enforcer, pid uint32) (terminateTarget, error) {
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ESRCH):
			return nil, fmt.Errorf("enforcement: terminate pid %d: %w", pid, errProcessGone)
		case errors.Is(err, unix.ENOSYS):
			return nil, fmt.Errorf("enforcement: refusing to terminate pid %d: pidfd_open unavailable (kernel < 5.3), cannot pin the target safely", pid)
		}
		return nil, fmt.Errorf("enforcement: refusing to terminate pid %d: pidfd_open: %w", pid, err)
	}
	t := &pidfdTarget{fd: fd}

	if err := classifyForTerminate(procRoot, pid, e.cwpEntries()); err != nil {
		t.Close()
		return nil, err
	}
	// The /proc reads above describe the process the pidfd points at only if
	// it was still alive while they happened (otherwise its PID could have
	// been reused). Signal 0 on the pidfd confirms that.
	if err := unix.PidfdSendSignal(fd, 0, nil, 0); err != nil {
		t.Close()
		if errors.Is(err, unix.ESRCH) {
			return nil, fmt.Errorf("enforcement: terminate pid %d: %w", pid, errProcessGone)
		}
		return nil, fmt.Errorf("enforcement: refusing to terminate pid %d: pidfd liveness check: %w", pid, err)
	}
	return t, nil
}

type pidfdTarget struct{ fd int }

func (t *pidfdTarget) Kill() error { return unix.PidfdSendSignal(t.fd, unix.SIGKILL, nil, 0) }
func (t *pidfdTarget) Close()      { unix.Close(t.fd) }

// SetCWPSource tells the enforcer where to read the currently loaded CWP
// workload registry. Until it is set, only the CPM rules apply here (the
// sensor still enforces whatever registry it was pushed).
func (e *Enforcer) SetCWPSource(fn func() []ipc.CWPWorkloadEntry) {
	e.cwpMu.Lock()
	e.cwpSource = fn
	e.cwpMu.Unlock()
}

func (e *Enforcer) cwpEntries() []ipc.CWPWorkloadEntry {
	e.cwpMu.RLock()
	defer e.cwpMu.RUnlock()
	if e.cwpSource == nil {
		return nil
	}
	return e.cwpSource()
}

// classifyForTerminate returns nil when pid may be terminated, otherwise an
// error naming the gate and reason. Anything it cannot determine counts as
// protected.
func classifyForTerminate(root string, pid uint32, cwp []ipc.CWPWorkloadEntry) error {
	if pid == 1 {
		return refuse("CPM", pid, "Critical Operating System Process (PID 1)")
	}
	dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))

	if flags, ok := readStatFlags(dir); ok && flags&pfKthread != 0 {
		return refuse("CPM", pid, "Kernel Thread")
	}
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		if _, serr := os.Stat(dir); os.IsNotExist(serr) {
			return fmt.Errorf("enforcement: terminate pid %d: %w", pid, errProcessGone)
		}
		// No executable link is also what a kernel thread looks like.
		return refuse("CPM", pid, "executable cannot be resolved (kernel thread or unreadable); failing closed")
	}
	// A binary replaced on disk reads back as "<path> (deleted)"; protect it
	// under its original path too.
	for _, cand := range []string{exe, strings.TrimSuffix(exe, " (deleted)")} {
		for _, p := range cpmProtectedExecPaths {
			if samePathKey(cand, p) {
				return refuse("CPM", pid, "Protected Executable "+p)
			}
		}
	}
	return classifyCWP(dir, pid, strings.TrimSuffix(exe, " (deleted)"), cwp)
}

func classifyCWP(dir string, pid uint32, exe string, cwp []ipc.CWPWorkloadEntry) error {
	for _, w := range cwp {
		if !samePathKey(exe, w.Path) {
			continue
		}
		if w.IdentityTier == 0 { // path tier: the path alone is the identity
			return refuse("CWP", pid, "Administrator Protected Workload (path) "+w.Path)
		}
		// Hash tier: protected only if this really is the registered binary.
		// The pid-relative exe link is hashed, so the bytes are those of the
		// running image, not whatever sits at the path now.
		sum, err := hashFile(filepath.Join(dir, "exe"))
		if err != nil {
			return refuse("CWP", pid, "cannot hash executable for identity verification; failing closed")
		}
		if w.ExpectedHash == [sha256.Size]byte{} {
			return refuse("CWP", pid, "registry entry has no expected hash; failing closed")
		}
		if sum == w.ExpectedHash {
			return refuse("CWP", pid, "Administrator Protected Workload (hash-verified) "+w.Path)
		}
		log.Printf("[CWP] SECURITY EVENT — hash mismatch for %s (pid=%d): not the registered workload, eligible for termination", w.Path, pid)
	}
	return nil
}

func refuse(gate string, pid uint32, reason string) error {
	return fmt.Errorf("enforcement: refusing to terminate pid %d: %s: %s", pid, gate, reason)
}

// samePathKey compares two paths the way the sensor's 64-byte map keys do.
func samePathKey(a, b string) bool {
	if len(a) > pathKeyLen {
		a = a[:pathKeyLen]
	}
	if len(b) > pathKeyLen {
		b = b[:pathKeyLen]
	}
	return a == b
}

// readStatFlags returns the process flags field of <dir>/stat.
func readStatFlags(dir string) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return 0, false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	// After the comm: state ppid pgrp session tty_nr tpgid flags ...
	f := strings.Fields(s[i+1:])
	if len(f) < 7 {
		return 0, false
	}
	flags, err := strconv.ParseUint(f[6], 10, 64)
	return flags, err == nil
}

func hashFile(path string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
