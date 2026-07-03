import socket
import os
import struct

sock_path = "/var/run/kbd.sock"

if os.path.exists(sock_path):
    os.remove(sock_path)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(1)

print(f"Listening on {sock_path}...")

conn, _ = s.accept()
print("Client connected.")

STATE_FMT = (
    "<"
    "HBB"      # magic, version, msg_type
    "III"      # pid, ppid, uid
    "16s"      # comm
    "QQ"       # start_time_ns, last_updated_ns
    "6d"       # dim_score[6]
    "dd"       # composite_score, ema_score
    "II"       # zone, event_count
)

TRANS_FMT = (
    "<"
    "HBB"      # magic, version, msg_type
    "III"      # pid, from_zone, to_zone
    "d"        # score
    "Q"        # timestamp
)

while True:
    header = conn.recv(4)
    if not header:
        break

    (length,) = struct.unpack("<I", header)

    payload = b""
    while len(payload) < length:
        chunk = conn.recv(length - len(payload))
        if not chunk:
            raise RuntimeError("Socket closed unexpectedly")
        payload += chunk

    magic, version, msg_type = struct.unpack("<HBB", payload[:4])

    print("\n" + "=" * 70)
    print(f"Magic   : 0x{magic:04X}")
    print(f"Version : {version}")
    print(f"Type    : {msg_type}")

    if msg_type == 1:
        (
            magic,
            version,
            msg_type,
            pid,
            ppid,
            uid,
            comm,
            start_ns,
            updated_ns,
            d0,
            d1,
            d2,
            d3,
            d4,
            d5,
            composite,
            ema,
            zone,
            event_count,
        ) = struct.unpack(STATE_FMT, payload)

        comm = comm.split(b"\0", 1)[0].decode(errors="replace")

        print("PROCESS STATE")
        print(f" PID         : {pid}")
        print(f" PPID        : {ppid}")
        print(f" UID         : {uid}")
        print(f" COMM        : {comm}")
        print(f" Start NS    : {start_ns}")
        print(f" Updated NS  : {updated_ns}")
        print(f" Dim Scores  :")
        print(f"   [0] {d0:.2f}")
        print(f"   [1] {d1:.2f}")
        print(f"   [2] {d2:.2f}")
        print(f"   [3] {d3:.2f}")
        print(f"   [4] {d4:.2f}")
        print(f"   [5] {d5:.2f}")
        print(f" Composite   : {composite:.2f}")
        print(f" EMA         : {ema:.2f}")
        print(f" Zone        : {zone}")
        print(f" Event Count : {event_count}")

    elif msg_type == 2:
        (
            magic,
            version,
            msg_type,
            pid,
            from_zone,
            to_zone,
            score,
            ts_ns,
        ) = struct.unpack(TRANS_FMT, payload)

        print("ZONE TRANSITION")
        print(f" PID         : {pid}")
        print(f" From Zone   : {from_zone}")
        print(f" To Zone     : {to_zone}")
        print(f" Score       : {score:.2f}")
        print(f" Timestamp   : {ts_ns}")

    else:
        print(f"Unknown message type: {msg_type}")

conn.close()
s.close()
