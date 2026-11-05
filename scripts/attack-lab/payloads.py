#!/usr/bin/env python3
"""
Scenario payloads for the KB attack lab. Run by runner.py, one per execution:

    python3 payloads.py <scenario> --workdir DIR --actions FILE [--seed N]

Each payload is the ROOT of its own process tree (the runner starts it in a new
session), so everything it spawns can be attributed to the execution from the
process tree alone.

Safety by construction (also asserted in tests/test_attack_lab.py):
  * network: loopback only (127.0.0.0/8). assert_loopback() refuses anything else.
  * files: everything the payload creates lives under --workdir. The only files
    it reads outside it are the same credential/system files a real intruder
    would touch (/etc/shadow via sudo, /etc/passwd, ~/.ssh keys); contents are
    discarded, never stored or printed.
  * no exploit code. "Attacks" reproduce the observable BEHAVIOUR (credential
    reads, privilege transitions, cross-process memory writes, beaconing, RWX
    memory) against throwaway processes the payload itself starts.
  * run only on an isolated lab VM. runner.py requires --ack-isolated.

Ground truth: every payload appends {"ts_ns", "action"} lines to --actions
(wall-clock ns). The first line with "malicious": true marks the first
malicious action, used later to measure time-to-containment.
"""
import argparse
import ctypes
import glob
import ipaddress
import json
import mmap
import os
import random
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time

LOOPBACK = ipaddress.ip_network("127.0.0.0/8")


def assert_loopback(host: str):
    if ipaddress.ip_address(host) not in LOOPBACK:
        raise ValueError(f"attack lab refuses non-loopback address {host}")


class Actions:
    def __init__(self, path):
        self.f = open(path, "a", buffering=1)

    def __call__(self, name, malicious=False, **kw):
        self.f.write(json.dumps({"ts_ns": time.time_ns(), "action": name,
                                 "malicious": malicious, **kw}) + "\n")


def run(cmd, **kw):
    kw.setdefault("stdout", subprocess.DEVNULL)
    kw.setdefault("stderr", subprocess.DEVNULL)
    kw.setdefault("timeout", 60)
    try:
        return subprocess.run(cmd, **kw).returncode
    except (subprocess.TimeoutExpired, OSError):
        return -1


# --------------------------------------------------------------------------
# Attacks
# --------------------------------------------------------------------------

def credential_access(wd, rng, act):
    for rnd in range(3):
        act("read_shadow_via_sudo", malicious=True, round=rnd)
        run(["sudo", "-n", "cat", "/etc/shadow"])
        act("read_gshadow_via_sudo", malicious=True, round=rnd)
        run(["sudo", "-n", "cat", "/etc/gshadow"])
        act("read_passwd", round=rnd)
        open("/etc/passwd").read()
        for key in glob.glob(os.path.expanduser("~/.ssh/id_*")):
            if not key.endswith(".pub"):
                act("read_ssh_private_key", malicious=True, round=rnd)
                try:
                    open(key, "rb").read(1)  # one byte: the access is the signal
                except OSError:
                    pass
        time.sleep(rng.uniform(0.5, 1.5))


def privilege_escalation(wd, rng, act):
    attempts = [
        ["sudo", "-n", "true"],
        ["sudo", "-n", "-u", "root", "id"],
        ["sudo", "-n", "-l"],
        ["unshare", "-Ur", "id"],          # user-namespace capability gain
        ["su", "-c", "id"],                # fails without a tty: still a transition attempt
        ["sudo", "-n", "sh", "-c", "id; cat /proc/1/environ >/dev/null"],
    ]
    for rnd in range(3):
        for cmd in attempts:
            act("privilege_attempt", malicious=True, cmd=" ".join(cmd[:3]), round=rnd)
            run(cmd, timeout=15)
            time.sleep(rng.uniform(0.1, 0.5))


def process_injection(wd, rng, act):
    """ptrace + process_vm_writev into a throwaway child we start ourselves."""
    victim = subprocess.Popen(
        [sys.executable, "-c",
         "import mmap,sys,time\nm=mmap.mmap(-1,4096)\n"
         "import ctypes\nprint(ctypes.addressof(ctypes.c_char.from_buffer(m)),flush=True)\n"
         "time.sleep(60)"],
        stdout=subprocess.PIPE, text=True)
    addr = int(victim.stdout.readline())
    libc = ctypes.CDLL(None, use_errno=True)
    PTRACE_ATTACH, PTRACE_DETACH = 16, 17

    class IOV(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]

    libc.process_vm_writev.argtypes = [ctypes.c_int, ctypes.POINTER(IOV), ctypes.c_ulong,
                                       ctypes.POINTER(IOV), ctypes.c_ulong, ctypes.c_ulong]
    libc.process_vm_writev.restype = ctypes.c_ssize_t
    try:
        for rnd in range(6):
            act("ptrace_attach", malicious=True, target=victim.pid, round=rnd)
            libc.ptrace(PTRACE_ATTACH, victim.pid, 0, 0)
            time.sleep(0.2)  # let the attach settle
            payload = ctypes.create_string_buffer(b"\x90" * 64)  # harmless bytes
            local = IOV(ctypes.cast(payload, ctypes.c_void_p), 64)
            remote = IOV(addr, 64)
            act("process_vm_writev", malicious=True, target=victim.pid, round=rnd)
            libc.process_vm_writev(victim.pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
            libc.ptrace(PTRACE_DETACH, victim.pid, 0, 0)
            time.sleep(rng.uniform(0.3, 1.0))
    finally:
        victim.kill()


def network_c2(wd, rng, act):
    """Beaconing plus a port sweep, all against loopback addresses."""
    beacon_host, sweep_host = "127.0.0.2", "127.0.0.3"
    assert_loopback(beacon_host), assert_loopback(sweep_host)
    for i in range(25):  # fixed-interval beacon: the timing regularity is the signal
        act("beacon", malicious=True, n=i)
        s = socket.socket()
        s.settimeout(0.5)
        s.connect_ex((beacon_host, 4444))
        s.close()
        time.sleep(1.0)
    act("port_sweep", malicious=True)
    for port in range(20, 140):
        s = socket.socket()
        s.settimeout(0.2)
        s.connect_ex((sweep_host, port))
        s.close()


def memory_exploit(wd, rng, act):
    for rnd in range(8):
        act("mmap_rwx", malicious=True, round=rnd)
        m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        m.write(b"\xc3" * 16)  # 'ret' bytes, never executed
        m.close()
        act("mmap_then_mprotect_exec", malicious=True, round=rnd)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                              ctypes.c_int, ctypes.c_long]
        p = libc.mmap(None, 4096, 3, 0x22, -1, 0)  # RW, private|anonymous
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.mprotect(p, 4096, 5)                  # -> R-X
        libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.munmap(p, 4096)
        time.sleep(rng.uniform(0.2, 0.8))


def evasion_slow(wd, rng, act):
    """Low-and-slow credential access + beaconing: renamed binary, long gaps,
    work spread over short-lived children, jittered intervals."""
    assert_loopback("127.0.0.4")
    renamed = os.path.join(wd, "updater")
    shutil.copy("/bin/cat", renamed)
    for i in range(8):
        act("slow_cred_read", malicious=True, n=i)
        run(["sudo", "-n", renamed, "/etc/shadow"])
        time.sleep(rng.uniform(3.0, 6.0))
        act("slow_beacon", malicious=True, n=i)
        run([sys.executable, "-c",
             "import socket;s=socket.socket();s.settimeout(.5);s.connect_ex(('127.0.0.4',8443));s.close()"])
        time.sleep(rng.uniform(2.0, 5.0))


def exfil_staging(wd, rng, act):
    """MATCHED PAIR with benign_backup_etc: the same `tar` over /etc, but it stages
    only the secrets into a hidden file and then phones out. Context, not the
    binary, is what differs (what is archived, where it lands, what follows)."""
    assert_loopback("127.0.0.2")
    stage = os.path.join(wd, ".cache-update.tgz")
    for rnd in range(3):
        act("stage_secrets_with_tar", malicious=True, round=rnd)
        run(["sudo", "-n", "tar", "czf", stage, "/etc/shadow", "/etc/gshadow", "/etc/ssh"])
        for k in range(3):
            act("send_out", malicious=True, round=rnd, n=k)
            s_ = socket.socket()
            s_.settimeout(0.3)
            s_.connect_ex(("127.0.0.2", 8443))
            s_.close()
            time.sleep(0.3)
        try:
            os.remove(stage)
        except OSError:
            pass
        time.sleep(rng.uniform(0.5, 1.5))


def credential_dump(wd, rng, act):
    """MATCHED PAIR with benign_credential_audit: both read /etc/shadow with a
    standard tool as root. The attack writes the whole file out and then
    connects to a C2-style port; the audit only counts."""
    assert_loopback("127.0.0.2")
    loot = os.path.join(wd, ".d")
    for rnd in range(3):
        act("dump_shadow_to_file", malicious=True, round=rnd)
        with open(loot, "wb") as f:
            run(["sudo", "-n", "cat", "/etc/shadow"], stdout=f)
        act("beacon_after_dump", malicious=True, round=rnd)
        s_ = socket.socket()
        s_.settimeout(0.3)
        s_.connect_ex(("127.0.0.2", 4444))
        s_.close()
        time.sleep(rng.uniform(0.5, 1.5))


# --------------------------------------------------------------------------
# Benign workloads
# --------------------------------------------------------------------------

def compile_workload(wd, rng, act):
    cc = shutil.which("gcc") or shutil.which("cc")
    objs = []
    for i in range(8):
        src = os.path.join(wd, f"m{i}.c")
        with open(src, "w") as f:
            f.write(f"#include <stdio.h>\nint f{i}(int x){{return x*{i + 2};}}\n")
            if i == 0:
                f.write("int main(void){printf(\"%d\\n\",f0(2));return 0;}\n")
        act("compile", unit=i)
        run([cc, "-O1", "-c", src, "-o", src[:-1] + "o"])
        objs.append(src[:-1] + "o")
    act("link")
    run([cc, objs[0], "-o", os.path.join(wd, "a.out")])


def database_workload(wd, rng, act):
    db = sqlite3.connect(os.path.join(wd, "bench.db"))
    db.execute("create table t(id integer primary key, v text)")
    for batch in range(40):
        act("db_batch", n=batch)
        db.executemany("insert into t(v) values (?)", [(str(rng.random()),) for _ in range(100)])
        db.commit()
        db.execute("select count(*), max(v) from t").fetchall()
    db.close()


def web_workload(wd, rng, act):
    port = rng.randint(18800, 18899)
    server = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1",
                               "--directory", wd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.0)
        for i in range(60):
            act("http_get", n=i)
            run(["curl", "-s", "-o", "/dev/null", f"http://127.0.0.1:{port}/"], timeout=5)
            time.sleep(0.1)
    finally:
        server.kill()


def admin_workload(wd, rng, act):
    cmds = [["ls", "-R", "/etc"], ["ps", "aux"], ["df", "-h"], ["ss", "-tn"],
            ["find", "/usr/share", "-maxdepth", "2", "-name", "*.txt"],
            ["grep", "-r", "Port", "/etc/ssh"], ["uname", "-a"], ["id"], ["w"]]
    for rnd in range(3):
        for c in cmds:
            act("admin_cmd", cmd=c[0])
            run(c)
            time.sleep(rng.uniform(0.1, 0.4))


def admin_privileged_workload(wd, rng, act):
    """HARD NEGATIVES: legitimate administration that touches the same
    sensitive files and privilege transitions the attacks do (backup of /etc
    including /etc/shadow, service inspection through sudo). A policy that
    cannot tell these from credential_access is not usable."""
    cmds = [["sudo", "-n", "systemctl", "status", "kbd", "--no-pager"],
            ["sudo", "-n", "tar", "cf", os.path.join(wd, "etc-backup.tar"), "/etc"],
            ["sudo", "-n", "journalctl", "-n", "50", "--no-pager"],
            ["sudo", "-n", "apt", "list", "--installed"],
            ["sudo", "-n", "ls", "-l", "/root"]]
    for rnd in range(2):
        for c in cmds:
            act("privileged_admin_cmd", cmd=" ".join(c[2:4]))
            run(c, timeout=60)
            time.sleep(rng.uniform(0.3, 1.0))


def backup_etc_workload(wd, rng, act):
    """MATCHED PAIR with exfil_staging: the same `sudo tar` over /etc (which includes
    /etc/shadow), written to a normal backup location (the scratch dir), verified by
    checksum, with no network activity."""
    for rnd in range(3):
        archive = os.path.join(wd, f"etc-backup-{rnd}.tgz")
        act("backup_etc", round=rnd)
        run(["sudo", "-n", "tar", "czf", archive, "/etc"], timeout=90)
        act("verify_backup", round=rnd)
        run(["sudo", "-n", "sha256sum", archive])
        time.sleep(rng.uniform(0.5, 1.5))


def credential_audit_workload(wd, rng, act):
    """MATCHED PAIR with credential_dump: the same root read of /etc/shadow with
    standard tools, as a password-policy audit would do (counts and checks only:
    nothing is written out, nothing connects out)."""
    audits = [["sudo", "-n", "grep", "-c", "^root:", "/etc/shadow"],
              ["sudo", "-n", "awk", "-F:", "$2==\"\" {n++} END {print n+0}", "/etc/shadow"],
              ["sudo", "-n", "wc", "-l", "/etc/shadow"]]
    for rnd in range(3):
        for c in audits:
            act("credential_audit", cmd=c[2], round=rnd)
            run(c)
            time.sleep(rng.uniform(0.2, 0.6))


class _Sink(threading.Thread):
    """A loopback 'remote host' that accepts a connection and counts what it receives, so
    the benign upload scenarios make a REAL connection that moves real bytes."""

    def __init__(self, host):
        super().__init__(daemon=True)
        assert_loopback(host)
        self.srv = socket.socket()
        self.srv.bind((host, 0))
        self.srv.listen(4)
        self.srv.settimeout(1.0)
        self.port = self.srv.getsockname()[1]
        self.received = 0
        self._stop_flag = threading.Event()

    def run(self):
        while not self._stop_flag.is_set():
            try:
                c, _ = self.srv.accept()
            except (socket.timeout, OSError):
                continue
            with c:
                while True:
                    data = c.recv(65536)
                    if not data:
                        break
                    self.received += len(data)

    def close(self):
        self._stop_flag.set()
        self.join(timeout=2)
        self.srv.close()


def _upload(host, port, path):
    n = 0
    with socket.create_connection((host, port), timeout=5) as c, open(path, "rb") as f:
        while chunk := f.read(65536):
            c.sendall(chunk)
            n += len(chunk)
    return n


def backup_remote_workload(wd, rng, act):
    """HARD NEGATIVE for any 'secret read + network' rule, matched to exfil_staging:
    the same `sudo tar` over /etc (including /etc/shadow), then an upload to a backup
    host, i.e. a legitimate offsite backup. Reads secrets AND uses the network."""
    sink = _Sink("127.0.0.3")
    sink.start()
    try:
        for rnd in range(3):
            archive = os.path.join(wd, f"etc-offsite-{rnd}.tgz")
            act("backup_etc", round=rnd)
            run(["sudo", "-n", "tar", "czf", archive, "/etc"], timeout=90)
            sent = _upload("127.0.0.3", sink.port, archive)
            act("upload_to_backup_host", round=rnd, bytes=sent)
            time.sleep(rng.uniform(0.5, 1.5))
    finally:
        sink.close()


def credential_report_workload(wd, rng, act):
    """HARD NEGATIVE for 'secret read + network', matched to credential_dump: the same
    root read of /etc/shadow, but only counts are computed and a small summary is sent
    to a compliance/monitoring endpoint, as an audit agent would."""
    sink = _Sink("127.0.0.3")
    sink.start()
    try:
        for rnd in range(3):
            act("credential_audit", round=rnd)
            out = os.path.join(wd, f"report-{rnd}.json")
            with open(out, "w") as f:
                run(["sudo", "-n", "grep", "-c", "^root:", "/etc/shadow"], stdout=f)
            sent = _upload("127.0.0.3", sink.port, out)
            act("report_to_monitoring", round=rnd, bytes=sent)
            time.sleep(rng.uniform(0.3, 0.8))
    finally:
        sink.close()


def idle_workload(wd, rng, act):
    act("idle")
    time.sleep(25)


# --------------------------------------------------------------------------
# Real-byte scenarios (added 2026-11-05, plan Workstream D). The original attacks above only
# connect_ex() to loopback addresses with no listener, so they transmit nothing and a byte
# counter cannot tell them from silence. These move REAL bytes to a loopback sink inside the
# payload's own process tree, in matched attack / benign pairs. Still loopback only, no exploit
# code, files under --workdir. Existing scenarios are untouched so earlier corpora stay comparable.
# --------------------------------------------------------------------------

BULK_MIB = (16, 48)        # size range of the generated bulk blob (tests shrink it)
SLOW_SENDS = 8             # sends in the slow exfil (tests shrink it)
BEACONS = 20               # check-ins in the beacon scenarios (tests shrink it)
SHARED_PORTS = (8443, 9001, 9100)   # attack and benign draw from the SAME ports so a port cannot leak the label


def _write_blob(path, mib, rng):
    """Filler that stands in for a database dump or data set, 1 MiB at a time. Archived with plain `tar cf`
    (no compression), so the bytes on the wire equal the size on disk."""
    with open(path, "wb") as f:
        for _ in range(mib):
            f.write(bytes(rng.getrandbits(8) for _ in range(256)) * 4096)   # 1 MiB, cheap to generate
    return os.path.getsize(path)


class _ReplySink(threading.Thread):
    """Loopback 'server' for beacons: reads one message per connection and answers with a short reply."""

    def __init__(self, host, port=0):
        super().__init__(daemon=True)
        assert_loopback(host)
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, port))
        self.srv.listen(8)
        self.srv.settimeout(0.5)
        self.port = self.srv.getsockname()[1]
        self.received = 0
        self._stop_flag = threading.Event()

    def run(self):
        while not self._stop_flag.is_set():
            try:
                c, _ = self.srv.accept()
            except (socket.timeout, OSError):
                continue
            with c:
                c.settimeout(2.0)
                try:
                    while True:
                        data = c.recv(65536)
                        if not data:
                            break
                        self.received += len(data)
                        c.sendall(b"ok" * 32)
                except OSError:
                    pass

    def close(self):
        self._stop_flag.set()
        self.join(timeout=2)
        self.srv.close()


def _beacon(host, port, payload):
    """One check-in: connect, send, read the reply, close. Returns bytes sent."""
    with socket.create_connection((host, port), timeout=3) as c:
        c.sendall(payload)
        c.settimeout(2.0)
        try:
            c.recv(4096)
        except OSError:
            pass
    return len(payload)


def exfil_small_real(wd, rng, act):
    """Credential-theft-sized exfiltration: stage ONLY the secrets (a few KB), then really upload
    them. MATCHED with benign_telemetry_small (same size class, no secrets) and with
    exfil_staging, which stages the same files but sends nothing."""
    sink = _Sink("127.0.0.2")
    sink.start()
    try:
        for rnd in range(rng.randint(2, 4)):
            stage = os.path.join(wd, f".u{rnd}.tgz")
            act("stage_secrets_with_tar", malicious=True, round=rnd)
            run(["sudo", "-n", "tar", "czf", stage, "/etc/shadow", "/etc/gshadow", "/etc/ssh"])
            if os.path.exists(stage):
                sent = _upload("127.0.0.2", sink.port, stage)
                act("send_out", malicious=True, round=rnd, bytes=sent)
            time.sleep(rng.uniform(0.5, 1.5))
    finally:
        sink.close()


def exfil_bulk_real(wd, rng, act):
    """Bulk exfiltration: /etc (secrets included) plus a large data blob, really uploaded.
    By volume this looks like a backup; MATCHED with benign_backup_bulk. Only context (what is
    archived and why) differs, which is the point of the pair."""
    sink = _Sink("127.0.0.2")
    sink.start()
    try:
        blob = os.path.join(wd, ".data.bin")
        mib = rng.randint(*BULK_MIB)
        act("stage_data", malicious=True, mib=mib)
        _write_blob(blob, mib, rng)
        archive = os.path.join(wd, ".pack.tgz")
        act("stage_secrets_with_tar", malicious=True)
        run(["sudo", "-n", "tar", "cf", archive, "/etc/shadow", "/etc/gshadow", "/etc/ssh", blob], timeout=90)
        if os.path.exists(archive):
            sent = _upload("127.0.0.2", sink.port, archive)
            act("send_out", malicious=True, bytes=sent)
    finally:
        sink.close()


def exfil_slow_real(wd, rng, act):
    """Low-and-slow exfiltration: a few KB every few seconds. The per-send volume is small and
    the timing regular; MATCHED with benign_telemetry_small on volume."""
    sink = _Sink("127.0.0.2")
    sink.start()
    try:
        stage = os.path.join(wd, ".s.tgz")
        act("stage_secrets_with_tar", malicious=True)
        run(["sudo", "-n", "tar", "czf", stage, "/etc/shadow", "/etc/gshadow", "/etc/ssh"])
        data = open(stage, "rb").read() if os.path.exists(stage) else b"x" * 2048
        for k in range(SLOW_SENDS):
            chunk = data[k * 512:(k + 1) * 512] or b"x" * 512
            with socket.create_connection(("127.0.0.2", sink.port), timeout=3) as c:
                c.sendall(chunk)
            act("send_out", malicious=True, n=k, bytes=len(chunk))
            time.sleep(rng.uniform(4.0, 6.0))
    finally:
        sink.close()


def c2_beacon_real(wd, rng, act):
    """Command-and-control beaconing with real check-ins: a fixed interval, a small payload and a
    reply, with an occasional larger 'result' upload. MATCHED with benign_heartbeat_real, which has
    the same interval, size and ports; only the process and file-access context differs."""
    port = rng.choice(SHARED_PORTS)
    srv = _ReplySink("127.0.0.4", port)
    srv.start()
    try:
        interval = rng.uniform(0.8, 1.2)
        for i in range(BEACONS):
            act("beacon", malicious=True, n=i)
            sent = _beacon("127.0.0.4", srv.port, os.urandom(rng.randint(120, 260)))
            if i % 7 == 6:
                act("result_upload", malicious=True, n=i)
                sent += _beacon("127.0.0.4", srv.port, os.urandom(20000))
            time.sleep(interval)
    finally:
        srv.close()


def backup_bulk_workload(wd, rng, act):
    """HARD NEGATIVE matched to exfil_bulk_real: /etc plus a large data set archived and uploaded
    to a backup host, the same size class as the bulk exfiltration."""
    sink = _Sink("127.0.0.3")
    sink.start()
    try:
        blob = os.path.join(wd, "dataset.bin")
        mib = rng.randint(*BULK_MIB)
        act("prepare_dataset", mib=mib)
        _write_blob(blob, mib, rng)
        archive = os.path.join(wd, "full-backup.tar")
        act("backup_etc_and_data")
        run(["sudo", "-n", "tar", "cf", archive, "/etc", blob], timeout=90)
        if os.path.exists(archive):
            sent = _upload("127.0.0.3", sink.port, archive)
            act("upload_to_backup_host", bytes=sent)
    finally:
        sink.close()


def heartbeat_real_workload(wd, rng, act):
    """HARD NEGATIVE matched to c2_beacon_real: an agent's monitoring heartbeat with the same
    interval, payload size and ports, plus an occasional metrics upload."""
    port = rng.choice(SHARED_PORTS)
    srv = _ReplySink("127.0.0.5", port)
    srv.start()
    try:
        interval = rng.uniform(0.8, 1.2)
        for i in range(BEACONS):
            act("heartbeat", n=i)
            sent = _beacon("127.0.0.5", srv.port, os.urandom(rng.randint(120, 260)))
            if i % 7 == 6:
                act("metrics_upload", n=i)
                sent += _beacon("127.0.0.5", srv.port, os.urandom(20000))
            time.sleep(interval)
    finally:
        srv.close()


def telemetry_small_workload(wd, rng, act):
    """HARD NEGATIVE matched to exfil_small_real and exfil_slow_real: about 20 to 40 KB per upload of non-secret
    system information (uname, disk usage, OS release and a package inventory, trimmed to 20 to 40 KB
    per upload) sent to a monitoring endpoint. No shell is used (a `sh -c` made an earlier version look like a no-tty
    shell to the SPAWNED_SHELL rule) and the size is in the same class as the small exfiltration."""
    sink = _Sink("127.0.0.3")
    sink.start()
    try:
        for rnd in range(rng.randint(2, 4)):
            report = os.path.join(wd, f"inventory-{rnd}.txt")
            act("collect_inventory", round=rnd)
            with open(report, "w") as f:
                run(["uname", "-a"], stdout=f)
                run(["df", "-h"], stdout=f)
                run(["cat", "/etc/os-release"], stdout=f)
                if run(["dpkg-query", "-W"], stdout=f) != 0:        # package inventory; fall back to a binary listing
                    run(["ls", "-l", "/usr/bin"], stdout=f)
            # keep each upload in the size class of exfil_small_real (about 25 KiB per round): the full
            # package inventory is ~70 KiB, which overshot the attack's size by a factor of 2 to 3
            with open(report, "r+b") as f:
                f.truncate(rng.randint(20_000, 40_000))
            sent = _upload("127.0.0.3", sink.port, report)
            act("upload_inventory", round=rnd, bytes=sent)
            time.sleep(rng.uniform(0.5, 1.5))
    finally:
        sink.close()


SCENARIOS = {
    # name: (kind, family, function, approx_seconds)
    "credential_access":      ("attack", "credential_access",    credential_access,       8),
    "privilege_escalation":   ("attack", "privilege_escalation", privilege_escalation,     8),
    "process_injection":      ("attack", "process_injection",    process_injection,        8),
    "network_c2":             ("attack", "network_c2",           network_c2,              35),
    "memory_exploit":         ("attack", "memory_exploit",       memory_exploit,           8),
    "evasion_slow":           ("attack", "evasion",              evasion_slow,            60),
    "exfil_staging":          ("attack", "exfil_staging",        exfil_staging,           12),
    "credential_dump":        ("attack", "credential_dump",      credential_dump,          8),
    "benign_compile":         ("benign", "compile",              compile_workload,        10),
    "benign_database":        ("benign", "database",             database_workload,       10),
    "benign_web":             ("benign", "web",                  web_workload,            15),
    "benign_admin":           ("benign", "admin",                admin_workload,          15),
    "benign_admin_privileged":("benign", "admin_privileged",     admin_privileged_workload, 25),
    "benign_idle":            ("benign", "idle",                 idle_workload,           26),
    "benign_backup_etc":      ("benign", "backup_etc",           backup_etc_workload,     14),
    "benign_credential_audit":("benign", "credential_audit",     credential_audit_workload, 8),
    "benign_backup_remote":   ("benign", "backup_remote",        backup_remote_workload,  14),
    "benign_credential_report":("benign", "credential_report",   credential_report_workload, 8),
    # real-byte scenarios (see the section above)
    "exfil_small_real":       ("attack", "exfil_small",          exfil_small_real,        12),
    "exfil_bulk_real":        ("attack", "exfil_bulk",           exfil_bulk_real,         25),
    "exfil_slow_real":        ("attack", "exfil_slow",           exfil_slow_real,         50),
    "c2_beacon_real":         ("attack", "c2_real",              c2_beacon_real,          28),
    "benign_backup_bulk":     ("benign", "backup_bulk",          backup_bulk_workload,    25),
    "benign_heartbeat_real":  ("benign", "heartbeat",            heartbeat_real_workload, 28),
    "benign_telemetry_small": ("benign", "telemetry_small",      telemetry_small_workload, 12),
}


# Scenario groups for runner.py --scenarios. "legacy" is exactly the 18 scenarios of the corpora captured
# before the real-byte scenarios existed (use it to stay comparable with them); "real_bytes" is the new set.
REAL_BYTE_NAMES = ("exfil_small_real", "exfil_bulk_real", "exfil_slow_real", "c2_beacon_real",
                   "benign_backup_bulk", "benign_heartbeat_real", "benign_telemetry_small")
GROUPS = {
    "all": tuple(sorted(SCENARIOS)),
    "legacy": tuple(sorted(n for n in SCENARIOS if n not in REAL_BYTE_NAMES)),
    "real_bytes": tuple(sorted(REAL_BYTE_NAMES)),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=sorted(SCENARIOS))
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--actions", required=True)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    os.makedirs(a.workdir, exist_ok=True)
    act = Actions(a.actions)
    act("start", scenario=a.scenario)
    try:
        SCENARIOS[a.scenario][2](a.workdir, random.Random(a.seed), act)
    finally:
        act("end", scenario=a.scenario)


if __name__ == "__main__":
    main()
