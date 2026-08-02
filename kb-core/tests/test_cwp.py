# Mock Control Plane driver for CWP (Critical Workload Protection).
# See docs/features/CWP.md — verifies handle_incoming_containment_cmd()'s
# cwp_classify() gate (kb-core/userspace/sensor/kbd_sensor.c), evaluated
# strictly after cpm_classify(): a path-tier protected workload and a
# hash-tier protected workload (correct hash) are both rejected for
# containment; a hash-tier workload whose binary content doesn't match
# its expected hash ("spoofed identity") is NOT protected and is
# contained normally, with a distinct security-event log line; an
# ordinary unprotected process is still contained (regression check).
#
# Usage:
#   Terminal 1: sudo ./build/kbd_sensor
#   Terminal 2: sudo python3 tests/test_cwp.py
#
# Same dual-socket setup as test_cpm.py (see that file's header comment
# for the kbd.sock/kbct.sock split rationale) — reused verbatim here.

import hashlib
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

telemetry_sock_path = os.getenv("KBD_SOCKET_PATH", "/run/kb/kbd.sock")
control_sock_path = os.getenv("KBD_CONTROL_SOCKET_PATH", "/run/kb/kbct.sock")

os.makedirs(os.path.dirname(telemetry_sock_path), exist_ok=True)
os.makedirs(os.path.dirname(control_sock_path), exist_ok=True)


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
    print("kbd_sensor connected (control) — containment commands and the CWP workload push go out on this one.")
except KeyboardInterrupt:
    print("\nExiting.")
    sys.exit(0)


def _drain_inbound(c):
    try:
        while True:
            data = c.recv(65536)
            if not data:
                return
    except OSError:
        return


threading.Thread(target=_drain_inbound, args=(telemetry_conn,), daemon=True).start()

# Wire format constants matching kb_bridge.h and kbd_sensor.c
MsgMagic = 0x4B42
WireVersion = 3
MsgTypeContainmentCmd = 5
MsgTypeCwpWorkloads = 8

CWP_TIER_PATH = 0
CWP_TIER_HASH = 1


def send_containment_cmd(pid, level, reason):
    reason_bytes = reason.encode('utf-8')[:64]
    reason_padded = reason_bytes + b'\0' * (64 - len(reason_bytes))

    payload = struct.pack("<II64s", pid, level, reason_padded)
    header = struct.pack("<HBB", MsgMagic, WireVersion, MsgTypeContainmentCmd)
    frame_len = len(header) + len(payload)
    length_prefix = struct.pack("<I", frame_len)

    conn.sendall(length_prefix + header + payload)
    print(f"Sent Containment Command: PID={pid}, Level={level}, Reason='{reason}'")


def send_cwp_workloads(entries):
    # entries: list of (path, tier, expected_hash_bytes_or_None)
    header = struct.pack("<HBB", MsgMagic, WireVersion, MsgTypeCwpWorkloads)
    body = struct.pack("<I", len(entries))
    for path, tier, expected_hash in entries:
        path_bytes = path.encode('utf-8')[:63]
        path_padded = path_bytes + b'\0' * (64 - len(path_bytes))
        hash_bytes = (expected_hash or b'\0' * 32)[:32]
        hash_padded = hash_bytes + b'\0' * (32 - len(hash_bytes))
        body += struct.pack("<64sB32s", path_padded, tier, hash_padded)

    frame_len = len(header) + len(body)
    length_prefix = struct.pack("<I", frame_len)
    conn.sendall(length_prefix + header + body)
    print(f"Pushed CWP workload registry: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.digest()


BPFTOOL = "/usr/local/bin/bpftool"


def dump_contained_pids():
    try:
        import json
        maps = json.loads(subprocess.check_output([BPFTOOL, "-j", "map", "show"]))
        match = next((m for m in maps if m.get("name", "").startswith("contained_pids")), None)
        if not match:
            return "(no contained_pids_map found — was it ever loaded?)"
        return subprocess.check_output(
            [BPFTOOL, "map", "dump", "id", str(match["id"])],
            stderr=subprocess.STDOUT,
        ).decode()
    except Exception as e:
        return f"(bpftool dump failed: {e})"


try:
    # Two real distinct binaries to protect by path — /bin/sleep (path
    # tier) and a private copy of /bin/cat (hash tier, correct hash), plus
    # a third private copy of /bin/cat whose content is altered after
    # policy push, to exercise the spoofed-identity path (§7/§11.1/§13.3).
    workdir = "/tmp/kb_cwp_test"
    os.makedirs(workdir, exist_ok=True)

    path_tier_bin = shutil.which("sleep") or "/bin/sleep"

    hash_tier_bin_good = os.path.join(workdir, "protected_good")
    shutil.copyfile(shutil.which("cat") or "/bin/cat", hash_tier_bin_good)
    os.chmod(hash_tier_bin_good, 0o755)
    good_hash = sha256_of(hash_tier_bin_good)

    hash_tier_bin_spoofed = os.path.join(workdir, "protected_spoofed")
    shutil.copyfile(shutil.which("cat") or "/bin/cat", hash_tier_bin_spoofed)
    os.chmod(hash_tier_bin_spoofed, 0o755)
    # Wrong hash on purpose: this entry's *expected* hash does not match
    # hash_tier_bin_spoofed's real content, simulating policy pinned to a
    # known-good hash while the on-disk binary has been tampered with.
    wrong_hash = hashlib.sha256(b"this is not the real binary content").digest()

    send_cwp_workloads([
        (os.path.realpath(path_tier_bin), CWP_TIER_PATH, None),
        (os.path.realpath(hash_tier_bin_good), CWP_TIER_HASH, good_hash),
        (os.path.realpath(hash_tier_bin_spoofed), CWP_TIER_HASH, wrong_hash),
    ])
    time.sleep(1)

    # Test 1: path-tier protected workload — CWP_REJECT_PROTECTED_PATH.
    path_proc = subprocess.Popen([path_tier_bin, "100"])
    time.sleep(0.3)
    send_containment_cmd(path_proc.pid, 2, "CWP test: path-tier protected workload (expect REJECT)")
    time.sleep(1)

    # Test 2: hash-tier protected workload, correct hash —
    # CWP_REJECT_PROTECTED_HASH.
    hash_proc_good = subprocess.Popen([hash_tier_bin_good], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
    time.sleep(0.3)
    send_containment_cmd(hash_proc_good.pid, 2, "CWP test: hash-tier protected workload, correct hash (expect REJECT)")
    time.sleep(1)

    # Test 3: hash-tier entry whose live binary content does NOT match
    # the pushed expected hash — spoofed identity, NOT protected, expect
    # normal containment plus a "[CWP] SECURITY EVENT" log line on the
    # sensor's console.
    hash_proc_spoofed = subprocess.Popen([hash_tier_bin_spoofed], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
    time.sleep(0.3)
    send_containment_cmd(hash_proc_spoofed.pid, 1, "CWP test: hash-tier entry with WRONG hash (expect ACCEPT + security event)")
    time.sleep(1)

    # Test 4: regression check — an ordinary unprotected process must
    # still be contained normally.
    target = subprocess.Popen(["sleep", "100"])
    time.sleep(0.3)
    send_containment_cmd(target.pid, 1, "CWP test: ordinary process (expect ACCEPT)")
    time.sleep(1)

    print("\n--- contained_pids_map dump ---")
    print("Expect the spoofed-identity PID and the ordinary-process PID here —")
    print("the path-tier and correct-hash PIDs must be absent.")
    print(dump_contained_pids())

    # Cleanup
    for pid in (path_proc.pid, hash_proc_good.pid, hash_proc_spoofed.pid, target.pid):
        send_containment_cmd(pid, 0, "CWP test cleanup")
    time.sleep(0.5)
    for p in (path_proc, hash_proc_good, hash_proc_spoofed, target):
        p.terminate()
        p.wait()
    shutil.rmtree(workdir, ignore_errors=True)

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
