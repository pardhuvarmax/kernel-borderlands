#!/usr/bin/env python3
"""
Host-side thermal and frequency log for captures and benchmarks (experiment E3).

    hostlog.py OUT.csv [--interval 5] [--seconds N]      run on the HOST, beside a VM window; Ctrl-C or --seconds to stop

A guest cannot see the host's package temperature or clock, and throttling on the host is the leading explanation for
the VM freezes and for some of the heavy-lag runs (internal report, section on thermal effects). One row per sample:
UTC time, package temperature (C, from `sensors`), mean/min/max current CPU frequency (MHz, from cpufreq), 1-minute
load average. Missing sources are written as empty fields, never as zero.
"""
import argparse
import csv
import glob
import re
import subprocess
import sys
import time


def package_temp():
    try:
        out = subprocess.run(["sensors"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    m = re.search(r"Package id 0:\s*\+?(-?[\d.]+)", out) or re.search(r"(?:Tctl|Tdie|CPU)[^:]*:\s*\+?(-?[\d.]+)", out)
    return m.group(1) if m else ""


def freqs_mhz():
    vals = []
    for p in glob.glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq"):
        try:
            vals.append(int(open(p).read()) / 1000.0)
        except (OSError, ValueError):
            pass
    if not vals:
        return "", "", ""
    return "%.0f" % (sum(vals) / len(vals)), "%.0f" % min(vals), "%.0f" % max(vals)


def load1():
    try:
        return open("/proc/loadavg").read().split()[0]
    except OSError:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--seconds", type=float, default=0.0, help="0 = until interrupted")
    a = ap.parse_args()
    t_end = time.time() + a.seconds if a.seconds else None
    with open(a.out, "a", newline="", buffering=1) as f:
        w = csv.writer(f)
        if f.tell() == 0:
            w.writerow(["utc", "package_temp_c", "freq_mean_mhz", "freq_min_mhz", "freq_max_mhz", "load1"])
        try:
            while t_end is None or time.time() < t_end:
                fm, fmin, fmax = freqs_mhz()
                w.writerow([time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), package_temp(), fm, fmin, fmax, load1()])
                time.sleep(a.interval)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
