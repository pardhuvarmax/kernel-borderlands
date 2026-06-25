# Enforcement Layer

Applies graduated containment to processes based on zone classification.

## Containment Ladder
1. Observe        — passive monitoring (SAFE zone)
2. Restrict       — seccomp net-block (SUSPICIOUS zone)
3. Isolate        — namespaces + cgroup (BORDERLANDS zone)
4. Terminate      — SIGKILL (score = 100 + authorization)

## Primitives
- Linux Namespaces (mnt, net, user)
- Seccomp filters (libseccomp)
- Cgroup v2 throttling
- SIGKILL (last resort)

## Key Principle
Every non-terminal action is reversible on score normalization.
