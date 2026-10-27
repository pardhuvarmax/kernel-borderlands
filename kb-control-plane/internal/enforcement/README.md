# Enforcement Layer

Applies graduated containment to processes based on zone classification.

## Containment Ladder
1. Observe        — passive monitoring (SAFE zone)
2. Restrict       — seccomp net-block (SUSPICIOUS zone)
3. Isolate        — namespaces + cgroup (BORDERLANDS zone)
4. Terminate      — SIGKILL (score = 100 + authorization)

Terminate is the only level that kills. `Enforcer.Contain` first runs the Go-side CPM/CWP gate (`guard.go`):
PID 1, kernel threads, protected executables and registered workloads are refused, and anything it cannot
identify is refused too. Only then does it send level 4 to the sensor (which applies its own CPM/CWP gates
before writing `contained_pids_map`) and, once that command was sent, SIGKILL the process through a pidfd.
The dashboard's Isolate button uses level 3 (Namespace), which does not kill; Kill is a separate action
(`POST /api/kill`).

## Primitives
- Linux Namespaces (mnt, net, user)
- Seccomp filters (libseccomp)
- Cgroup v2 throttling
- SIGKILL (last resort)

## Key Principle
Every non-terminal action is reversible on score normalization.
