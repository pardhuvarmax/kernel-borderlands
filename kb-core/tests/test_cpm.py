# Mock Control Plane driver for CPM (Critical Process Module).
# See docs/features/CPM.md — verifies handle_incoming_containment_cmd()'s
# cpm_classify() gate (kb-core/userspace/sensor/kbd_sensor.c) rejects
# containment of PID 1, kernel threads, and kbd_sensor's own PID, while
# still allowing containment of an ordinary unprotected process.
#
# Usage:
#   Terminal 1: sudo ./build/kbd_sensor
#   Terminal 2: sudo python3 tests/test_cpm.py
# (sudo needed in terminal 2 too, for the bpftool map dump verification
# step and to spawn/kill the regression-check target process.)
#
# Wire format matches test_restore_ipc.py exactly — see that file for the
# frame-layout rationale (STOPGAP WIRE FORMAT note in kb_bridge.h).
#
# TWO sockets, not one: kbd.sock/kbct.sock split (see kb_bridge.h's
# KB_BRIDGE_CONTROL_SOCK comment and docs/development/core-control/
# control-plane-catalog.md §5.3) means kbd_sensor now reads containment
# commands from control_fd (kbct.sock) exclusively — bridge_fd (kbd.sock)
# is telemetry-only, write-only from the sensor's side, never read for
# incoming commands anymore. A version of this script that only bound
# kbd.sock (as this one originally did) would connect fine and receive
# telemetry, but every send_containment_cmd() call would go out on a
# connection kbd_sensor never reads for that purpose — silently doing
# nothing rather than erroring, which is worse than a crash.

import socket
import os
import struct
import sys
import time
import subprocess
import threading

# kb_bridge.h's KB_BRIDGE_DEFAULT_SOCK / KB_BRIDGE_CONTROL_SOCK (kbd_sensor's
# compiled-in defaults when KBD_SOCKET_PATH/KBD_CONTROL_SOCKET_PATH aren't
# set) are "/run/kb/kbd.sock"/"/run/kb/kbct.sock", not "/var/run/kbd.sock"
# as test_restore_ipc.py's (pre-split, telemetry-only) default assumes —
# matching kbd_sensor's real defaults here so this script works against an
# unmodified `sudo ./build/kbd_sensor` invocation without needing an env
# var override (which sudo strips by default unless the sudoers entry has
# SETENV).
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
    print("kbd_sensor connected (control) — containment commands go out on this one.")
except KeyboardInterrupt:
    print("\nExiting.")
    sys.exit(0)

# kbd_sensor sends its own telemetry (zone transitions, state syncs,
# process-exit events — see bridge_dispatch()/kb_bridge_send_process_exit()
# in kbd_sensor.c) over the telemetry connection, unprompted, independent
# of whatever we send on the control connection. On a busy box with a lot
# of process churn this can be substantial. If nothing here ever reads it,
# the socket send buffer on the sensor's side eventually fills, a send()
# fails, and (pre-SIGPIPE-fix behavior) kbd_sensor could treat that as
# "connection is dead" — drain and discard it in the background so the
# telemetry connection survives the whole test sequence regardless.
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


def send_containment_cmd(pid, level, reason):
    reason_bytes = reason.encode('utf-8')[:64]
    reason_padded = reason_bytes + b'\0' * (64 - len(reason_bytes))

    payload = struct.pack("<II64s", pid, level, reason_padded)
    header = struct.pack("<HBB", MsgMagic, WireVersion, MsgTypeContainmentCmd)
    frame_len = len(header) + len(payload)
    length_prefix = struct.pack("<I", frame_len)

    conn.sendall(length_prefix + header + payload)
    print(f"Sent Containment Command: PID={pid}, Level={level}, Reason='{reason}'")


def find_sensor_pid():
    # -x (exact comm match) rather than -f (full cmdline substring match):
    # -f would also match this script's own invocation and any sudo
    # supervisor/wrapper process whose cmdline happens to contain the
    # binary's path as an argument, not just the sensor process itself.
    try:
        out = subprocess.check_output(["pgrep", "-x", "kbd_sensor"]).decode().split()
        return int(out[0])
    except Exception:
        return None


BPFTOOL = "/usr/local/bin/bpftool"


def dump_contained_pids():
    # "contained_pids_map" is 19 characters, but in-kernel BPF object
    # names are capped at 15 usable chars (BPF_OBJ_NAME_LEN) — the
    # kernel silently truncates it to "contained_pids_", and bpftool's
    # `map dump name contained_pids_map` then fails with "can't parse
    # name" since that string can't possibly match anything in-kernel.
    # Same truncation hits protected_pids_map/protected_exec_paths_map.
    # Look the map up by ID instead: `map show` (JSON) still reports the
    # truncated name, so match on that prefix and dump by ID.
    #
    # Absolute path: this script is already root (via sudo), so no
    # further sudo is needed here — but sudo's secure_path often
    # excludes /usr/local/bin (where bpftool lives on this box), so a
    # bare "bpftool" lookup via PATH can fail even though the caller is
    # already privileged enough to run it.
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
    # Give the sensor a moment to finish CPM startup registration
    # (populate_protected_exec_paths / cpm_register_self /
    # cpm_reconcile_running_processes all run before the bridge is even
    # read, so this margin is generous, not load-bearing).
    time.sleep(1)

    # Test 1: PID 1 (init/systemd) — CPM_REJECT_PID1, structurally always
    # protected regardless of registry state.
    send_containment_cmd(1, 2, "CPM test: PID 1")
    time.sleep(1)

    # Test 2: PID 2 — kthreadd, a kernel thread on effectively every Linux
    # system. Exercises CPM_REJECT_KERNEL_THREAD (readlink /proc/2/exe
    # fails since kernel threads have no mm/exe).
    send_containment_cmd(2, 2, "CPM test: kernel thread (kthreadd)")
    time.sleep(1)

    # Test 3: kbd_sensor's own PID — CPM_REJECT_PROTECTED_PID via
    # cpm_register_self()'s startup self-registration.
    sensor_pid = find_sensor_pid()
    if sensor_pid:
        send_containment_cmd(sensor_pid, 2, "CPM test: sensor self-protection")
    else:
        print("Could not auto-detect kbd_sensor's PID (pgrep -f build/kbd_sensor found nothing) — skipping self-protection test")
    time.sleep(1)

    # Test 4: regression check — an ordinary unprotected process must
    # still be contained normally. Watch kbd_sensor's own output for
    # "[SENSOR] Applied containment level 1" for this PID, not
    # "[CPM] Containment Prevented".
    target = subprocess.Popen(["sleep", "100"])
    time.sleep(0.2)
    send_containment_cmd(target.pid, 1, "CPM test: ordinary process (expect ACCEPT)")
    time.sleep(1)

    print("\n--- contained_pids_map dump ---")
    print("Expect ONLY the ordinary-process PID above to appear here —")
    print("PID 1, the kernel thread, and the sensor's own PID must be absent.")
    print(dump_contained_pids())

    # Cleanup
    send_containment_cmd(target.pid, 0, "CPM test cleanup")
    time.sleep(0.5)
    target.terminate()
    target.wait()

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
