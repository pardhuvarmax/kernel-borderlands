# NOTE: updated for the kbd.sock/kbct.sock split (see kb_bridge.h's
# KB_BRIDGE_CONTROL_SOCK comment and docs/development/core-control/
# control-plane-catalog.md §5.3). kbd_sensor now reads containment commands
# from control_fd (kbct.sock) exclusively — bridge_fd (kbd.sock) is
# telemetry-only, write-only from the sensor's side. This script used to
# bind only kbd.sock and send containment commands there; post-split that
# would connect fine but every send_containment_cmd() call would go out on
# a connection kbd_sensor never reads for that purpose — silently doing
# nothing rather than erroring. Fixed by binding both sockets, same
# pattern as tests/test_cpm.py.

import socket
import os
import struct
import sys
import time

telemetry_sock_path = os.getenv("KBD_SOCKET_PATH", "/run/kb/kbd.sock")
control_sock_path = os.getenv("KBD_CONTROL_SOCKET_PATH", "/run/kb/kbct.sock")


def _fresh_listener(path):
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError as e:
            print(f"Could not remove existing socket {path}: {e}")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    sock.listen(1)
    return sock


telemetry_listener = _fresh_listener(telemetry_sock_path)
control_listener = _fresh_listener(control_sock_path)

print(f"Mock Control Plane listening on {telemetry_sock_path} (telemetry) and {control_sock_path} (control)...")
print("Please run kbd_sensor now (e.g., sudo ./build/kbd_sensor)")

try:
    telemetry_conn, _ = telemetry_listener.accept()
    print("kbd_sensor connected (telemetry).")
    conn, _ = control_listener.accept()
    print("kbd_sensor connected (control) — containment commands go out on this one.")
except KeyboardInterrupt:
    print("\nExiting.")
    sys.exit(0)

# Wire format constants matching types.go and kbd_sensor
MsgMagic = 0x4B42
WireVersion = 3
MsgTypeContainmentCmd = 5

def send_containment_cmd(pid, level, reason):
    reason_bytes = reason.encode('utf-8')[:64]
    reason_padded = reason_bytes + b'\0' * (64 - len(reason_bytes))
    
    # Pack payload: pid (uint32), level (uint32), reason (char[64])
    payload = struct.pack("<II64s", pid, level, reason_padded)
    
    # Pack header: magic (uint16), version (uint8), msg_type (uint8)
    header = struct.pack("<HBB", MsgMagic, WireVersion, MsgTypeContainmentCmd)
    
    # Framing: length prefix (4 bytes) covers header + payload size
    frame_len = len(header) + len(payload)
    length_prefix = struct.pack("<I", frame_len)
    
    conn.sendall(length_prefix + header + payload)
    print(f"Sent Containment Command: PID={pid}, Level={level}, Reason='{reason}'")

try:
    # Give the sensor a moment to initialize or read rules
    time.sleep(1)
    
    # 1. Send Isolate command (Level 1 / Cgroup)
    send_containment_cmd(9999, 1, "Simulated Isolation Trigger")
    time.sleep(2)
    
    # 2. Send Restore command (Level 0 / None)
    send_containment_cmd(9999, 0, "Restore Safe State")
    time.sleep(2)
    
except KeyboardInterrupt:
    pass
finally:
    conn.close()
    telemetry_conn.close()
    control_listener.close()
    telemetry_listener.close()
    for p in (control_sock_path, telemetry_sock_path):
        if os.path.exists(p):
            os.remove(p)
