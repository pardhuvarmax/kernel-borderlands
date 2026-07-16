import os
import sys
import time

# Add comms folder to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../comms")))

from comms.grpc_client import ControlPlaneClient
import kb_pb2

def run_verification():
    socket_path = "/run/kb/kba.sock"
    
    # Check if socket file exists
    if not os.path.exists(socket_path):
        print(f"❌ Error: Unix Domain Socket not found at {socket_path}")
        print("💡 Please make sure the Go Control Plane (kbd) is running and has initialized the socket.")
        sys.exit(1)
        
    print(f"🔌 Connecting to real Control Plane over UDS: {socket_path} ...")
    client = ControlPlaneClient(socket_path)
    
    try:
        # 1. Test process state query
        pid = os.getpid()
        print(f"🔍 Querying process state for current PID {pid}...")
        state = client.get_process_state(pid)
        print(f"✅ Success! Process details retrieved:")
        print(f"   - PID: {state.pid}")
        print(f"   - Comm: {state.comm}")
        print(f"   - Anomaly Score: {state.score}")
        print(f"   - Zone: {kb_pb2.Zone.Name(state.zone)}")
        print(f"   - Containment: {kb_pb2.ContainmentLevel.Name(state.containment)}")
        
        # 2. Test submitting a decision
        print(f"\n📤 Submitting a test agent decision...")
        ack = client.submit_decision(
            decision_id="verify-uds-999",
            agent_id="agent-verifier",
            pid=pid,
            action="MONITOR",
            confidence=0.85,
            authorized_by=["patroller-test"]
        )
        print(f"✅ Success! Decision Ack: {ack.success} (Message: '{ack.message}')")
        
        print("\n✨ Real UDS Connection Verification Complete! Comms layer is fully operational.")
        
    except Exception as e:
        print(f"❌ Error during gRPC UDS communication: {e}")
        sys.exit(1)
    finally:
        client.close()

if __name__ == "__main__":
    run_verification()
