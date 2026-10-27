# Enforcement Layer

Applies graduated containment to processes based on zone classification.

## Containment Ladder
1. Observe        — passive monitoring (SAFE zone)
2. Restrict       — seccomp net-block (SUSPICIOUS zone)
3. Isolate        — namespaces + cgroup (BORDERLANDS zone)
4. Terminate      — SIGKILL (score = 100 + authorization)

Terminate is the only level that kills: `Enforcer.Contain` writes level 4 to the sensor's
`contained_pids_map` (the LSM hooks then deny everything) and, once that command was sent, `kbd` itself
sends SIGKILL to the PID. The dashboard's Isolate button uses level 3 (Namespace), which does not kill;
Kill is a separate action (`POST /api/kill`).

## Primitives
- Linux Namespaces (mnt, net, user)
- Seccomp filters (libseccomp)
- Cgroup v2 throttling
- SIGKILL (last resort)

## Key Principle
Every non-terminal action is reversible on score normalization.
