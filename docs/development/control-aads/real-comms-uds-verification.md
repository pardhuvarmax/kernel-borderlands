# Walkthrough: Real Comms UDS Verification Guide

This guide explains how to perform a **real connection integration test** between the Python AADS client and the active Go Control Plane daemon (`kbd`) over the `/run/kb/kba.sock` Unix Domain Socket (UDS).

---

## 🏗️ Step 1: Build the Go Control Plane Daemon

Before running the verification, compile the `kbd` daemon:

```bash
cd kb-control-plane
go build -o kbd cmd/kbd/main.go
```

---

## 🚀 Step 2: Start the Go Daemon

Run the daemon with a local database and policy configuration. This will boot the gRPC server and initialize `/run/kb/kba.sock`:

```bash
# Ensure the runtime socket directory exists and is writable
sudo mkdir -p /run/kb
sudo chown -R $USER:kb-devs /run/kb

# Start the daemon
./kbd --db data/state.db --policy config/policy.yaml
```

---

## 🐍 Step 3: Run the Verification Script

Open a second terminal, activate the Python virtual environment in `kb-aads`, and run the verification script [verify_real_connection.py](file:///home/emergence/Desktop/kernel-borderlands/kb-aads/tests/verify_real_connection.py):

```bash
cd kb-aads
source venv/bin/activate
python3 tests/verify_real_connection.py
```

### Expected Output:
```text
🔌 Connecting to real Control Plane over UDS: /run/kb/kba.sock ...
🔍 Querying process state for current PID 12345...
✅ Success! Process details retrieved:
   - PID: 12345
   - Comm: python3
   - Anomaly Score: 0.0
   - Zone: SAFE
   - Containment: NONE

📤 Submitting a test agent decision...
✅ Success! Decision Ack: True (Message: 'Decision received and logged')

✨ Real UDS Connection Verification Complete! Comms layer is fully operational.
```

---

## 🔍 Step 4: Audit Daemon Log Outputs

Inspect the `kbd` daemon logs in your first terminal. You should see log traces confirming the incoming connections:

```text
[gRPC] GetProcessState called for PID=12345
[gRPC] SubmitAgentDecision called: Agent=agent-verifier, Action=MONITOR, Confidence=0.85
```
