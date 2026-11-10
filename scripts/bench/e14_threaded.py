#!/usr/bin/env python3
"""
Experiment E14: does the sensor's per-syscall counter see worker threads?

The syscall hook (kb-core/ebpf/kbd_sensor.bpf.c, kb_handle_syscall) returns early when the thread id differs from
the process id, so only a process's MAIN thread is counted. The syscall-entropy dimension of the score (weight 0.25)
is built from those counts. This script measures the gap against ground truth.

    e14_threaded.py --ack-vm --out DIR            live, on the isolated lab VM, beside the running sensor
    e14_threaded.py --dry-run --out DIR           offline: the "sensor" is SIMULATED as main-thread-only counting

Phases (each SECONDS long, total work held equal between 1 and 2/3):
  single      one thread does all four syscall mixes                          (control: sensor should see ~100%)
  threaded4   4 worker threads, one mix each, supervisory main thread
  threaded16  16 worker threads at a quarter of the per-thread rate
  server      thread-per-connection echo server (accept in main, read/write in handlers); ground truth is the
              process's /proc/<pid>/io syscr+syscw summed over ALL threads

For each phase it records the truth (the workload's own per-syscall counts, all threads and main thread), the sensor's
view (the per-(pid, syscall) counts map, dumped with bpftool), Shannon entropy of each distribution, the coverage ratio
(sensor-counted / truth), and, with the feed, the dim_syscall value kbd reports for the process.

Live mode changes NOTHING on the system: no service restart, no policy or unit change, no install. It runs a short
benign workload (reads /dev/zero and /etc/os-release, writes bytes to /dev/null, getppid/getuid/stat; loopback sockets
in the server phase) and reads BPF maps. It needs passwordless sudo for bpftool and refuses to run as root.
"""
import argparse
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
MAP_PREFIX_COUNTS = "kb_syscall_coun"   # BPF map names are truncated to 15 characters
MAP_PREFIX_TOTALS = "kb_syscall_tota"
RW_NRS = (0, 1)                          # read, write (x86_64)


# ----------------------------------------------------------------------------- pure helpers (unit-tested)
def entropy_bits(counts):
    """Shannon entropy in bits of a {key: count} distribution; 0.0 for an empty or single-valued one."""
    tot = sum(v for v in counts.values() if v > 0)
    if tot <= 0:
        return 0.0
    return -sum((v / tot) * math.log2(v / tot) for v in counts.values() if v > 0)


def _le_int(b):
    return int.from_bytes(bytes(b), "little")


def _as_int(x):
    """bpftool prints scalars as ints when the map has BTF, or as a list of '0x..' byte strings when it does not."""
    if isinstance(x, int):
        return x
    if isinstance(x, list):
        return _le_int([int(v, 16) if isinstance(v, str) else int(v) for v in x])
    if isinstance(x, str):
        return int(x, 0)
    raise ValueError("unsupported key/value form: %r" % (x,))


def parse_counts_dump(entries, pid):
    """entries: parsed JSON of `bpftool map dump id N -j` for kb_syscall_counts (key = pid<<32 | syscall_nr)."""
    out = {}
    for e in entries:
        e = e.get("formatted", e)
        k = _as_int(e["key"])
        if (k >> 32) == pid:
            out[k & 0xFFFFFFFF] = out.get(k & 0xFFFFFFFF, 0) + _as_int(e["value"])
    return out


def parse_totals_dump(entries, pid):
    for e in entries:
        e = e.get("formatted", e)
        if _as_int(e["key"]) == pid:
            return _as_int(e["value"])
    return 0


def coverage(sensor_counts, truth_counts):
    """Share of the truth that the sensor counted, per syscall number and in total."""
    tot_truth = sum(truth_counts.values())
    tot_sensor = sum(sensor_counts.get(nr, 0) for nr in truth_counts)
    per = {nr: (sensor_counts.get(nr, 0) / c if c else None) for nr, c in truth_counts.items()}
    return {"total": (tot_sensor / tot_truth if tot_truth else None), "per_syscall": per}


def summarize_phase(name, truth_all, truth_main, sensor):
    return {
        "phase": name,
        "truth_total": sum(truth_all.values()), "truth_main_total": sum(truth_main.values()),
        "sensor_total_on_truth_nrs": sum(sensor.get(nr, 0) for nr in truth_all), "sensor_counted_nrs": sorted(sensor),
        "entropy_bits": {"truth_all_threads": entropy_bits(truth_all), "truth_main_thread": entropy_bits(truth_main),
                         "sensor_counted": entropy_bits(sensor)},
        "coverage_of_all_threads": coverage(sensor, truth_all)["total"],
        "coverage_of_main_thread": coverage(sensor, truth_main)["total"],
    }


# ----------------------------------------------------------------------------- environment
def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sudo(cmd, **kw):
    return sh(["sudo", "-n"] + cmd, **kw)


def active(unit):
    return sh(["systemctl", "is-active", unit]).stdout.strip() == "active"


def preflight_live():
    if os.geteuid() == 0:
        sys.exit("run as an ordinary user (sudo -n is used for bpftool)")
    if sudo(["true"]).returncode != 0:
        sys.exit("passwordless sudo is required")
    if not (active("kbd") and active("kb-sensor")):
        sys.exit("kbd and kb-sensor must be active")
    if active("kb-checker"):
        sys.exit("kb-checker is running; it is held down on this VM, refusing to proceed")
    ids = find_map_ids()
    if not ids.get("counts"):
        sys.exit("kb_syscall_counts map not found: is the sensor's syscall hook loaded?")
    return ids


def find_map_ids():
    r = sudo(["bpftool", "map", "show", "-j"])
    ids = {}
    for m in json.loads(r.stdout or "[]"):
        n = m.get("name", "")
        if n.startswith(MAP_PREFIX_COUNTS):
            ids["counts"] = m["id"]
        elif n.startswith(MAP_PREFIX_TOTALS):
            ids["totals"] = m["id"]
    return ids


def dump_map(map_id):
    r = sudo(["bpftool", "map", "dump", "id", str(map_id), "-j"], timeout=60)
    if r.returncode != 0:
        raise RuntimeError("bpftool dump failed: " + r.stderr.strip())
    return json.loads(r.stdout)


# ----------------------------------------------------------------------------- workloads
def build_workload(outdir):
    exe = os.path.join(outdir, "threaded_load")
    r = sh(["gcc", "-O2", "-Wall", "-pthread", "-o", exe, os.path.join(HERE, "threaded_load.c")])
    if r.returncode != 0:
        sys.exit("gcc failed:\n" + r.stderr)
    return exe


def start_synthetic(exe, mode, threads, seconds, rate, out_json):
    p = subprocess.Popen([exe, mode, str(threads), str(seconds), str(rate), out_json], stdout=subprocess.PIPE, text=True)
    line = p.stdout.readline().strip()
    m = re.match(r"READY (\d+)", line)
    if not m:
        p.kill()
        sys.exit("workload did not start: %r" % line)
    return p, int(m.group(1))


SERVER_SRC = r'''
import os, socket, sys, threading, time
secs = int(sys.argv[1])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(64); s.settimeout(0.2)
print("READY", os.getpid(), s.getsockname()[1], flush=True)
end = time.monotonic() + secs
def handler(fd):
    try:
        while True:
            d = os.read(fd, 4096)
            if not d: break
            os.write(fd, d)
    except OSError:
        pass
    finally:
        os.close(fd)
while time.monotonic() < end:
    try:
        c, _ = s.accept()
    except socket.timeout:
        continue
    threading.Thread(target=handler, args=(c.detach(),), daemon=True).start()
time.sleep(0.3)
'''

CLIENT_SRC = r'''
import os, socket, sys, threading, time
port, conns, secs = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
end = time.monotonic() + secs
def run():
    s = socket.create_connection(("127.0.0.1", port))
    fd = s.detach(); msg = b"x" * 64
    while time.monotonic() < end:
        os.write(fd, msg); os.read(fd, 4096); time.sleep(0.001)   # paced: about 1000 requests/s per connection
    os.close(fd)
ts = [threading.Thread(target=run) for _ in range(conns)]
[t.start() for t in ts]; [t.join() for t in ts]
'''


def start_server(seconds, conns):
    srv = subprocess.Popen([sys.executable, "-c", SERVER_SRC, str(seconds)], stdout=subprocess.PIPE, text=True)
    m = re.match(r"READY (\d+) (\d+)", srv.stdout.readline().strip())
    if not m:
        srv.kill()
        sys.exit("server did not start")
    pid, port = int(m.group(1)), int(m.group(2))
    cli = subprocess.Popen([sys.executable, "-c", CLIENT_SRC, str(port), str(conns), str(max(1, seconds - 1))])
    return srv, cli, pid


def proc_io_all_threads(pid):
    """Sum of syscr+syscw over all threads (read/write-family syscalls); and the main thread's own."""
    def rd(path):
        d = {}
        with open(path) as f:
            for line in f:
                k, v = line.split(":")
                d[k.strip()] = int(v)
        return d.get("syscr", 0) + d.get("syscw", 0)
    allt = rd("/proc/%d/io" % pid)
    main = rd("/proc/%d/task/%d/io" % (pid, pid))
    return allt, main


# ----------------------------------------------------------------------------- feed (dim_syscall as kbd reports it)
def start_feed(path, socket_path):
    sys.path.insert(0, os.path.join(ROOT, "scripts", "attack-lab"))
    from capture import Capture
    cap = Capture(path, socket_path=socket_path)
    cap.start()
    return cap


def feed_dim_syscall(path, pid, since_ns):
    vals = []
    if not os.path.exists(path):
        return {"events": 0}
    with open(path) as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("pid") == pid and e.get("event_type") == "process_state" and e.get("recv_ns", 0) >= since_ns:
                try:
                    vals.append(float(e["metadata"]["dim_syscall"]))
                except (KeyError, ValueError):
                    pass
    if not vals:
        return {"events": 0}
    vals.sort()
    return {"events": len(vals), "min": vals[0], "median": vals[len(vals) // 2], "max": vals[-1]}


# ----------------------------------------------------------------------------- phases
def sensor_view(live, ids, pid, simulated):
    """Per-syscall counts the sensor holds for pid. In dry-run mode `simulated` is a main-thread-only stand-in."""
    if not live:
        return dict(simulated)
    return parse_counts_dump(dump_map(ids["counts"]), pid)


def run_phase(args, name, exe, outdir, ids, feed_path):
    seconds = args.seconds
    live = not args.dry_run
    rec = {"phase": name, "started": time.strftime("%Y-%m-%dT%H:%M:%S")}
    since = time.time_ns() + 3 * 10**9
    if name == "server":
        srv, cli, pid = start_server(seconds, args.server_conns)
        time.sleep(1.0)
        io0_all, io0_main = proc_io_all_threads(pid)
        time.sleep(max(1, seconds - 4))
        # sample before the server exits
        try:
            io1_all, io1_main = proc_io_all_threads(pid)
        except FileNotFoundError:
            sys.exit("server exited before sampling; raise --seconds")
        sim = {0: max(0, io1_main - io0_main)}     # DRY-RUN stand-in: main thread's reads/writes only
        counts = sensor_view(live, ids, pid, sim)
        srv.wait(timeout=seconds + 10)
        cli.wait(timeout=seconds + 10)
        truth_all = {RW_NRS[0]: max(0, io1_all - io0_all)}        # read+write family, all threads, lumped under nr 0
        truth_main = {RW_NRS[0]: max(0, io1_main - io0_main)}
        sensor_rw = {RW_NRS[0]: sum(counts.get(nr, 0) for nr in RW_NRS)} if live else {RW_NRS[0]: counts.get(0, 0)}
        rec.update(summarize_phase(name, truth_all, truth_main, sensor_rw))
        rec["note"] = ("ground truth is syscr+syscw (read/write-family syscalls, all threads) from /proc/<pid>/io; "
                       "the sensor figure is its read+write counts; the server's main thread only accepts")
        rec["pid"] = pid
    else:
        mode, threads, rate = {"single": ("single", 4, args.rate), "threaded4": ("threaded", 4, args.rate),
                               "threaded16": ("threaded", 16, max(1, args.rate // 4))}[name]
        out_json = os.path.join(outdir, "workload-%s.json" % name)
        t_start = time.monotonic()
        p, pid = start_synthetic(exe, mode, threads, seconds, rate, out_json)
        time.sleep(max(0.5, seconds - 1.0 - (time.monotonic() - t_start)))
        pre_end = sensor_view(live, ids, pid, {})          # counts held just before the workload ends
        p.wait(timeout=seconds + 20)
        post_exit = sensor_view(live, ids, pid, {})        # the counts map keys by pid and ages out by LRU, so entries persist
        truth = json.load(open(out_json))
        truth_all = {int(k): v for k, v in truth["all_counts"].items()}
        truth_main = {int(k): v for k, v in truth["main_counts"].items()}
        if live:
            sensor, which = (post_exit, "post_exit") if sum(post_exit.values()) > 0 else (pre_end, "pre_end (approximate: about 1 s short)")
        else:
            sensor, which = dict(truth_main), "SIMULATED (main-thread-only counting)"
        rec.update(summarize_phase(name, truth_all, truth_main, sensor))
        rec["sensor_sample"] = which
        rec["pre_end_counts"] = {str(k): v for k, v in pre_end.items()}
        rec["workload"] = {k: truth[k] for k in ("pid", "mode", "threads", "seconds", "rate_per_thread", "total_all", "total_main")}
        rec["pid"] = pid
    if feed_path:
        rec["feed_dim_syscall"] = feed_dim_syscall(feed_path, rec["pid"], since)
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ack-vm", action="store_true", help="this is the isolated lab VM; a short benign workload may run beside the sensor (live mode)")
    ap.add_argument("--dry-run", action="store_true", help="offline: simulate the sensor as main-thread-only counting; touches no BPF map")
    ap.add_argument("--phases", default="single,threaded4,threaded16,server")
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--rate", type=int, default=5000, help="work units per second per thread in the synthetic phases")
    ap.add_argument("--server-conns", type=int, default=8)
    ap.add_argument("--no-feed", action="store_true", help="do not read dim_syscall from the event feed")
    ap.add_argument("--socket", default="/run/kb/kba.sock")
    args = ap.parse_args()
    if not args.dry_run and not args.ack_vm:
        sys.exit("refusing: live mode runs a short workload beside the sensor; pass --ack-vm on the lab VM only")
    if not 10 <= args.seconds <= 60:
        sys.exit("--seconds must be 10-60")
    os.makedirs(args.out, exist_ok=True)
    ids = {} if args.dry_run else preflight_live()
    exe = build_workload(args.out)
    feed_path = None if (args.no_feed or args.dry_run) else os.path.join(args.out, "feed.jsonl")
    cap = start_feed(feed_path, args.socket) if feed_path else None
    results = []
    try:
        for name in args.phases.split(","):
            r = run_phase(args, name, exe, args.out, ids, feed_path)
            results.append(r)
            print("[e14] %-10s truth=%s sensor_on_truth_nrs=%s cover(all)=%s cover(main)=%s entropy(truth_all/main/sensor)=%.2f/%.2f/%.2f dim_syscall=%s" % (
                name, r["truth_total"], r["sensor_total_on_truth_nrs"],
                "%.3f" % r["coverage_of_all_threads"] if r["coverage_of_all_threads"] is not None else "-",
                "%.3f" % r["coverage_of_main_thread"] if r["coverage_of_main_thread"] is not None else "-",
                r["entropy_bits"]["truth_all_threads"], r["entropy_bits"]["truth_main_thread"], r["entropy_bits"]["sensor_counted"],
                r.get("feed_dim_syscall", "n/a")), flush=True)
    finally:
        if cap:
            cap.stop()
    meta = {"dry_run": args.dry_run, "seconds": args.seconds, "rate": args.rate, "kernel": os.uname().release,
            "host": os.uname().nodename, "date": time.strftime("%Y-%m-%dT%H:%M:%S")}
    with open(os.path.join(args.out, "e14-result.json"), "w") as f:
        json.dump({"meta": meta, "phases": results}, f, indent=1)
    print("wrote", os.path.join(args.out, "e14-result.json"))


if __name__ == "__main__":
    main()
