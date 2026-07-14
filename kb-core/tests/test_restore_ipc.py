import socket
import os
import struct
import sys
import time

# Socket path for the control plane UDS
sock_path = os.getenv("KBD_SOCKET_PATH", "/var/run/kbd.sock")

if os.path.exists(sock_path):
    try:
        os.remove(sock_path)
    except OSError as e:
        print(f"Could not remove existing socket {sock_path}: {e}")

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(1)

print(f"Mock Control Plane listening on {sock_path}...")
print("Please run kbd_sensor now (e.g., KBD_SOCKET_PATH={sock_path} sudo ./build/kbd_sensor)")

try:
    conn, _ = s.accept()
    print("kbd_sensor connected.")
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
    s.close()
    if os.path.exists(sock_path):
        os.remove(sock_path)
