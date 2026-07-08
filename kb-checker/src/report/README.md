# Recovery & Containment Dispatcher (`kb-checker/src/report/`)

This module coordinates alert dispatching and implements active mitigation containment playbooks when checks fail.

---

## 📂 Containment & Alerting Loops

### 1. Alert Dispatching
* Connects to `/run/kb/kba.sock` and submits structured gRPC `AgentDecision` reports.
* Differentiates threat severity:
  * Integrity breaches (signature mismatches, map tampering, hook bypasses) trigger `INTEGRITY_VIOLATION_CONTAIN`.
  * Service unreachable warnings trigger `SERVICE_UNAVAILABLE_WARNING`.

### 2. Watchdog Containment Fallback Hierarchy
If a critical integrity violation occurs and the primary `systemctl stop kb-sensor` command fails or times out:
* **Layer 1 (Force Kill)**: Sends `SIGKILL` (`pkill -9 kbd_sensor`) to terminate the userspace sensor daemon.
* **Layer 2 (Hook Detachment)**: Removes BPF link pins in `/sys/fs/bpf/`.
* **Layer 3 (Network Quarantine)**: Issues `iptables` firewall rules to drop all external incoming, outgoing, and forwarding network traffic, isolating the host from the cluster.
