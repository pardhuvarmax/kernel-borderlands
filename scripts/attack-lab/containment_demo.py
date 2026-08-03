#!/usr/bin/env python3
"""Long-running, LOCAL-ONLY demo trigger for the KB pipeline.

Run with: sudo python3 scripts/attack-lab/containment_demo.py [interval_seconds]

Does NOT implement any of the six scenarios named in scripts/attack-lab/README.md
(privilege_escalation.sh, reverse_shell.sh, lateral_movement.sh,
credential_access.sh, memory_exploit.sh, process_injection.sh) — those still
don't exist. No exploitation, no external network, no touching other
live processes.

Why this has to be one persistent Python process, not a shell loop calling
external commands: kb-core/userspace/behavior/kb_scoring.c scores per-PID,
where each of the 6 dimensions (syscall .25, process/privilege .20 each,
memory .15, file/network .10 each) keeps its "last known value" for that
PID's whole lifetime. A shell script that repeatedly forks `cat`/`python3 -`
resets scoring every round, since each fork is a brand-new PID starting from
zero — that was the bug in an earlier version of this demo
(containment_demo_loop.sh). Doing every action as plain syscalls inside one
long-lived interpreter, launched once under sudo (so the escalation flag
fires a single time at exec, per ebpf/kbd_sensor.bpf.c:428's
new_euid==0 check), lets all four dimensions accumulate on the same PID.
"""
import mmap
import os
import socket
import sys
import time

SECRET_PATH = "/tmp/kb-pipeline-test-secret.txt"
SHADOW_PATH = "/etc/shadow"
KBD_HTTP_PORT = 8080
INTERVAL = float(sys.argv[1]) if len(sys.argv) > 1 else 3.0


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def ensure_secret_file() -> None:
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "w") as f:
            f.write("demo secret\n")
        os.chmod(SECRET_PATH, 0o600)


def touch_file_dimension() -> None:
    for path in (SECRET_PATH, SHADOW_PATH):
        try:
            with open(path, "rb") as f:
                f.read(64)
        except OSError as e:
            log(f"  file read failed (non-fatal): {path}: {e}")


def touch_memory_dimension() -> None:
    # Benign self-mmap with RWX flags — the same pattern any JIT compiler
    # uses on its own memory. Not writing shellcode, not touching another
    # process, just allocating+freeing a page with those protection bits.
    m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    m.close()


def touch_network_dimension() -> None:
    # Loopback connect to kbd's own HTTP port — not an external connection.
    try:
        with socket.create_connection(("127.0.0.1", KBD_HTTP_PORT), timeout=1):
            pass
    except OSError as e:
        log(f"  loopback connect failed (non-fatal): {e}")


def main() -> None:
    if os.geteuid() != 0:
        print("Must run as root: sudo python3 scripts/attack-lab/containment_demo.py", file=sys.stderr)
        sys.exit(1)

    ensure_secret_file()
    pid = os.getpid()
    log(f"starting containment demo as PID {pid} (root, interval={INTERVAL}s). Ctrl+C to stop.")
    log("this single PID accumulates file+memory+network+privilege dimensions for its whole lifetime.")

    round_num = 0
    try:
        while True:
            round_num += 1
            log(f"── round {round_num} (still PID {pid}) ──")
            touch_file_dimension()
            touch_memory_dimension()
            touch_network_dimension()
            log(f"round {round_num} done — sleeping {INTERVAL}s")
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        log("stopping.")


if __name__ == "__main__":
    main()
