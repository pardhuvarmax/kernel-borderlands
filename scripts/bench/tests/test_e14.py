"""Offline tests for scripts/bench/e14_threaded.py (no BPF, no VM, no root)."""
import json
import math
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import e14_threaded as e14  # noqa: E402


def test_entropy():
    assert e14.entropy_bits({}) == 0.0
    assert e14.entropy_bits({1: 10}) == 0.0
    assert math.isclose(e14.entropy_bits({1: 5, 2: 5}), 1.0)
    assert math.isclose(e14.entropy_bits({1: 1, 2: 1, 3: 1, 4: 1}), 2.0)
    assert e14.entropy_bits({1: 0, 2: 7}) == 0.0


def test_parse_counts_btf_int_and_hex_bytes():
    pid = 4242
    key = (pid << 32) | 35
    btf = [{"key": key, "value": 7}, {"key": (999 << 32) | 1, "value": 3}]
    assert e14.parse_counts_dump(btf, pid) == {35: 7}
    raw = [{"key": ["0x%02x" % b for b in key.to_bytes(8, "little")], "value": ["0x07", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00"]}]
    assert e14.parse_counts_dump(raw, pid) == {35: 7}
    formatted = [{"formatted": {"key": key, "value": 9}}]
    assert e14.parse_counts_dump(formatted, pid) == {35: 9}


def test_parse_totals():
    assert e14.parse_totals_dump([{"key": 5, "value": 11}, {"key": 6, "value": 2}], 6) == 2
    assert e14.parse_totals_dump([], 6) == 0


def test_coverage_and_summary():
    truth_all = {0: 50, 1: 50}
    truth_main = {35: 10}
    sensor = {35: 10}
    s = e14.summarize_phase("x", {**truth_all, 35: 10}, truth_main, sensor)
    assert s["truth_total"] == 110 and s["truth_main_total"] == 10
    assert math.isclose(s["coverage_of_all_threads"], 10 / 110)
    assert math.isclose(s["coverage_of_main_thread"], 1.0)
    assert s["entropy_bits"]["sensor_counted"] == 0.0
    assert s["entropy_bits"]["truth_all_threads"] > 1.0


def _build(tmp):
    exe = os.path.join(tmp, "threaded_load")
    r = subprocess.run(["gcc", "-O2", "-Wall", "-pthread", "-o", exe, os.path.join(os.path.dirname(HERE), "threaded_load.c")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return exe


def _run(exe, mode, threads, tmp):
    out = os.path.join(tmp, mode + ".json")
    p = subprocess.run([exe, mode, str(threads), "1", "2000", out], capture_output=True, text=True, timeout=30)
    assert p.stdout.startswith("READY ")
    return json.load(open(out))


def test_workload_counts_threads_correctly():
    with tempfile.TemporaryDirectory() as tmp:
        exe = _build(tmp)
        t = _run(exe, "threaded", 4, tmp)
        s = _run(exe, "single", 4, tmp)
    assert t["total_main"] < 0.02 * t["total_all"]            # the main thread is supervisory
    assert s["total_main"] == s["total_all"]                  # the control does everything on the main thread
    assert {int(k) for k in t["all_counts"]} >= {0, 1, 3, 102, 110, 257}
    assert {int(k) for k in t["main_counts"]} <= {35, 257}    # nanosleep and the setup opens only


def test_workload_refuses_unsafe_arguments():
    with tempfile.TemporaryDirectory() as tmp:
        exe = _build(tmp)
        for args in (["threaded", "100", "5", "10"], ["threaded", "4", "500", "10"], ["threaded", "4", "5", "999999"]):
            r = subprocess.run([exe] + args + [os.path.join(tmp, "x.json")], capture_output=True, text=True)
            assert r.returncode == 2


def test_live_mode_requires_ack():
    r = subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE), "e14_threaded.py"), "--out", "/nonexistent-e14"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "ack-vm" in (r.stdout + r.stderr)
