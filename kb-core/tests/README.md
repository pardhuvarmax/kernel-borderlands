# KB Core Tests

Testing suites and verification utilities for the eBPF programs, behavior engine, and userspace sensor.

---

## Test Suites

### 1. Behavior Engine Unit Tests (`test_behavior.c`)
Tests the core state machine transitions, sequence validation, time windows, and rule matching logic:
*   **Running**:
    ```bash
    ./scripts/test.sh
    ```
*   **Verifies**:
    -   *State Transitions*: Evaluates safe $\to$ observed $\to$ suspicious $\to$ borderlands transitions.
    -   *Attack Chains*: Matches reverse shell and ptrace injection sequences.
    -   *Timing*: Validates time-window constraints on sequence patterns.

### 2. Live Hook Verification Script (`test_all_hooks.sh`)
Integration script that triggers all 9 telemetry event types sequentially to check live sensor performance.
*   **Passwordless Sudo Bypass**: Includes a helper `run_sudo_optional` that prompts for sudo authorization but gracefully times out after 5 seconds to bypass password blocks, continuing without sudo (failed opens still trigger VFS alerts!).
*   **Usage**:
    1.  Terminal 1: Start control plane and sensor.
    2.  Terminal 2: Run hook simulation script:
        ```bash
        ./tests/test_all_hooks.sh
        ```
*   **VFS and Hook Validation**: Triggers process execs, file accesses on `/etc/shadow` and `/etc/passwd`, outbound curls, raw socket binds, anonymous RWX maps, and `mprotect` W^X transitions.

### 3. CPM (Critical Process Module) Verification (`test_cpm.py`)
Mock Control Plane driver that binds **both** sockets in the `kbd.sock`/`kbct.sock` split (see [`docs/architecture/boot_sequence_spec.md`](../../docs/architecture/boot_sequence_spec.md)) and sends `kb_wire_containment_cmd` frames over the control socket (`kbct.sock`) to verify `cpm_classify()`'s gate in `handle_incoming_containment_cmd()` (see [`docs/features/CPM.md`](../../docs/features/CPM.md), [`docs/features/cpm-implementation.md`](../../docs/features/cpm-implementation.md)).
*   **Usage**:
    1.  Terminal 1: `sudo ./build/kbd_sensor` (binds `/run/kb/kbd.sock` and `/run/kb/kbct.sock` by default; override with `KBD_SOCKET_PATH`/`KBD_CONTROL_SOCKET_PATH` env vars if needed)
    2.  Terminal 2: `sudo python3 tests/test_cpm.py`
*   **Verifies**:
    -   PID 1 is rejected (`CPM_REJECT_PID1`).
    -   A kernel thread (PID 2 / `kthreadd`) is rejected (`CPM_REJECT_KERNEL_THREAD`).
    -   `kbd_sensor`'s own PID is rejected (`CPM_REJECT_PROTECTED_PID`, via startup self-registration).
    -   An ordinary unprotected process is still accepted and contained normally (regression check that CPM doesn't over-block), confirmed via `bpftool map dump name contained_pids_map` showing only that PID.
