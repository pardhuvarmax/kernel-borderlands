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
