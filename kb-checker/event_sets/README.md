# Attack Simulation Event Sets

JSON files describing simulated attack scenarios.
Used by the Runtime Sandbox to test scripts.

## Built-in Sets
- `privilege_escalation.json` — setuid/setcap sequences
- `reverse_shell.json`        — socket+connect+dup2+execve
- `lateral_movement.json`     — network scanning + SSH
- `credential_access.json`    — /etc/shadow access
- `memory_exploit.json`       — mmap/mprotect RWX patterns
- `normal_nginx.json`         — Benign nginx traffic (should NOT trigger)
- `normal_postgres.json`      — Benign postgres traffic (should NOT trigger)

## Format
```json
{
  "name": "reverse_shell",
  "should_trigger": true,
  "description": "Classic reverse shell pattern",
  "events": [
    {"type": "exec", "pid": 1234, "comm": "bash", "ppid": 999},
    {"type": "network", "pid": 1234, "dst": "192.168.1.100", "port": 4444}
  ]
}
```
