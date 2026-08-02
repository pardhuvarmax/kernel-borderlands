#!/usr/bin/env python3
"""
Phase 0 (scoped) — data collection for Containment's RL training set.

This is NOT the full Phase 0 pipeline described in the roadmap (that needs
real eBPF capture from isolated-VM attack-lab scenarios, per
docs/development/control-aads/aads-intelligence-roadmap.md). That doesn't
exist yet and can't be built overnight. This collects real (non-synthetic)
sources instead, chosen to match what kb-core actually watches — Linux
*syscall* behavior at the process level — not network flow, which is a
different observation surface KB doesn't monitor.

1. Attack + normal classes: the ADFA-LD dataset (Creech & Hu, UNSW Canberra)
   — real per-process Linux syscall-number traces, labeled by attack
   category. This is a host-based IDS dataset (syscall sequences), which is
   the same observation surface kb-core's eBPF sensor operates on, unlike
   network-flow datasets (NSL-KDD, CICIDS, etc.) which don't match what KB
   hunts. Categories present: Adduser, Hydra_FTP, Hydra_SSH,
   Java_Meterpreter, Meterpreter, Web_Shell, plus real Normal traces
   (Training_Data_Master / Validation_Data_Master).
   Pulled from a public GitHub mirror (verazuo/a-labelled-version-of-the-
   ADFA-LD-dataset) since no Kaggle API credentials are configured on this
   machine — same dataset content Kaggle also hosts, just fetched directly.
2. Supplementary benign class: real /proc telemetry sampled from this
   machine (load, network throughput, process count) — actually real,
   actually from "our own machine", folded in as extra normal-class
   diversity alongside ADFA-LD's own normal traces.

Known coverage gap, stated plainly: KB's attack-lab also names
`memory_exploit.sh` (mmap/mprotect RWX sequences) — ADFA-LD has no matching
category, so Containment's training data below does not cover that
scenario. Not silently glossed over: see label.py's module docstring.
"""
import csv
import io
import os
import time
import urllib.request
import zipfile

OUT_DIR = os.path.join(os.path.dirname(__file__), "output", "raw")
os.makedirs(OUT_DIR, exist_ok=True)

ADFA_ZIP_URL = "https://raw.githubusercontent.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset/master/ADFA-LD.zip"
ADFA_DIR = os.path.join(OUT_DIR, "ADFA-LD")

# ADFA-LD attack category -> KB attack-lab scenario this training run treats
# it as a stand-in for. Proposed mapping, not Karthik-confirmed (same status
# as other heuristic calls in this pipeline — see label.py).
ADFA_CATEGORY_TO_KB_SCENARIO = {
    "Adduser": "privilege_escalation",
    "Hydra_FTP": "credential_access",
    "Hydra_SSH": "lateral_movement",
    "Java_Meterpreter": "process_injection",
    "Meterpreter": "reverse_shell",
    "Web_Shell": "reverse_shell",
}


def fetch_adfa_ld():
    if os.path.isdir(ADFA_DIR):
        print(f"[collect] ADFA-LD already extracted at {ADFA_DIR}")
        return ADFA_DIR
    print(f"[collect] downloading ADFA-LD from {ADFA_ZIP_URL} ...")
    with urllib.request.urlopen(ADFA_ZIP_URL, timeout=60) as resp:
        data = resp.read()
    print(f"[collect] extracting {len(data) / 1024:.0f} KB zip ...")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(OUT_DIR)
    print(f"[collect] extracted to {ADFA_DIR}")
    return ADFA_DIR


def read_proc_loadavg():
    with open("/proc/loadavg") as f:
        parts = f.read().split()
    return float(parts[0]), float(parts[1]), float(parts[2])


def read_proc_netdev():
    total_rx, total_tx = 0, 0
    with open("/proc/net/dev") as f:
        lines = f.readlines()[2:]
    for line in lines:
        iface, rest = line.split(":", 1)
        if iface.strip() == "lo":
            continue
        fields = rest.split()
        total_rx += int(fields[0])
        total_tx += int(fields[8])
    return total_rx, total_tx


def read_proc_count():
    return sum(1 for entry in os.listdir("/proc") if entry.isdigit())


def collect_benign_samples(n_samples: int = 60, interval_sec: float = 1.0):
    """Real /proc-derived samples from this machine, labeled benign."""
    out_path = os.path.join(OUT_DIR, "local_benign.csv")
    if os.path.exists(out_path):
        print(f"[collect] local benign samples already present at {out_path}")
        return out_path

    print(f"[collect] sampling {n_samples} real /proc snapshots from this machine "
          f"({interval_sec}s apart, ~{n_samples * interval_sec:.0f}s total) ...")

    rows = []
    prev_rx, prev_tx = read_proc_netdev()
    for i in range(n_samples):
        time.sleep(interval_sec)
        load1, load5, load15 = read_proc_loadavg()
        rx, tx = read_proc_netdev()
        nproc = read_proc_count()
        rows.append({
            "load1": load1,
            "load5": load5,
            "net_rx_delta": max(0, rx - prev_rx),
            "net_tx_delta": max(0, tx - prev_tx),
            "nproc": nproc,
        })
        prev_rx, prev_tx = rx, tx
        if (i + 1) % 10 == 0:
            print(f"[collect]   {i + 1}/{n_samples} samples")

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"[collect] wrote {len(rows)} real benign samples to {out_path}")
    return out_path


if __name__ == "__main__":
    fetch_adfa_ld()
    collect_benign_samples()
