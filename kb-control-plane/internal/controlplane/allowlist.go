package controlplane

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/policy"
)

// trustedExecDirs are the directories a process's REAL executable must be in
// for an allowlist entry to be honoured. comm is chosen by the process itself,
// so a name match alone proves nothing. (A merged-/usr system resolves /bin
// and /sbin to /usr/bin, but both spellings are listed.) Anything under /tmp,
// a home directory or a deleted binary is never trusted.
var trustedExecDirs = []string{
	"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
	"/usr/lib/systemd/", "/lib/systemd/", "/usr/libexec/",
}

// resolveExe returns the target of /proc/<pid>/exe. A variable so tests can
// stand in for the filesystem.
var resolveExe = func(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}

func trustedExecutable(path string) bool {
	if path == "" || strings.HasSuffix(path, " (deleted)") {
		return false
	}
	for _, d := range trustedExecDirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

type allowlistHolder struct {
	mu   sync.RWMutex
	list *policy.Allowlist
	path string
}

// SetAllowlist installs the operator's allowlist; path is remembered so a
// policy reload can re-read it. Called from cmd/kbd after New() (New's
// signature is deliberately unchanged).
func (cp *ControlPlane) SetAllowlist(path string, a *policy.Allowlist) {
	cp.allow.mu.Lock()
	cp.allow.list, cp.allow.path = a, path
	cp.allow.mu.Unlock()
}

// reloadAllowlist re-reads allowlist.yaml from the remembered path.
func (cp *ControlPlane) reloadAllowlist() error {
	cp.allow.mu.RLock()
	path := cp.allow.path
	cp.allow.mu.RUnlock()
	if path == "" {
		return nil
	}
	a, err := policy.LoadAllowlist(path)
	if err != nil {
		return err
	}
	cp.allow.mu.Lock()
	cp.allow.list = a
	cp.allow.mu.Unlock()
	return nil
}

// allowlisted reports whether pid is exempt from AUTOMATIC containment: its
// comm is on the allowlist AND its running executable resolves under a trusted
// system directory. Fails closed: a process that has already exited, or whose
// binary cannot be resolved, is not exempt.
func (cp *ControlPlane) allowlisted(pid uint32, comm string) (reason string, exe string, ok bool) {
	cp.allow.mu.RLock()
	list := cp.allow.list
	cp.allow.mu.RUnlock()
	reason, listed := list.Match(comm)
	if !listed {
		return "", "", false
	}
	exe, err := resolveExe(pid)
	if err != nil || !trustedExecutable(exe) {
		return "", exe, false
	}
	return reason, exe, true
}
