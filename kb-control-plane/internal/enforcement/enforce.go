package enforcement

import (
    "fmt"
    "log"
    "os"
    "syscall"

    pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
)

type Enforcer struct{}

func New() *Enforcer { return &Enforcer{} }

func (e *Enforcer) Apply(pid uint32, level pb.ContainmentLevel) {
    switch level {
    case pb.ContainmentLevel_CGROUP:
        e.cgroupThrottle(pid)
    case pb.ContainmentLevel_SECCOMP:
        log.Printf("[ENFORCE] seccomp (TODO) PID=%d", pid)
    case pb.ContainmentLevel_NAMESPACE:
        log.Printf("[ENFORCE] namespace isolation (TODO) PID=%d", pid)
    case pb.ContainmentLevel_TERMINATE:
        e.sigkill(pid)
    default:
        log.Printf("[ENFORCE] no-op level=%v PID=%d", level, pid)
    }
}

func (e *Enforcer) cgroupThrottle(pid uint32) {
    dir := "/sys/fs/cgroup/kb_contained"
    os.MkdirAll(dir, 0755)
    os.WriteFile(dir+"/cpu.max", []byte("5000 100000\n"), 0644)
    f, err := os.OpenFile(dir+"/cgroup.procs", os.O_WRONLY|os.O_APPEND, 0)
    if err != nil { log.Printf("[ENFORCE] cgroup open: %v", err); return }
    defer f.Close()
    fmt.Fprintf(f, "%d\n", pid)
    log.Printf("[ENFORCE] cgroup throttle applied PID=%d", pid)
}

func (e *Enforcer) sigkill(pid uint32) {
    proc, err := os.FindProcess(int(pid))
    if err != nil { log.Printf("[ENFORCE] FindProcess: %v", err); return }
    if err := proc.Signal(syscall.SIGKILL); err != nil {
        log.Printf("[ENFORCE] SIGKILL PID=%d: %v", pid, err)
        return
    }
    log.Printf("[ENFORCE] SIGKILL PID=%d", pid)
}