#!/usr/bin/env bash
#
# Kernel Borderlands — automatic dev environment installer.
# Referenced by docs/getting-started/installation.md ("Automatic Installation").
# Idempotent: safe to re-run; skips steps whose output already exists.
#
# What this does NOT do: build/run any KB binary, create /run/kb, or touch
# /etc/kb — see docs/development/full-pipeline-run-guide.md for the run steps.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

log() { printf '\n\033[1;32m==>\033[0m %s\n' "$1"; }
warn() { printf '\n\033[1;33m!!\033[0m %s\n' "$1" >&2; }

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        warn "$1 not found on PATH — install it before continuing (see docs/getting-started/installation.md#required-software)."
        return 1
    fi
}

# ── 1. Required system packages ─────────────────────────────────────────
log "Checking required tooling (git, python3, go, node, cargo, clang, make, bpftool)"
missing=0
for c in git python3 go node cargo clang make; do
    require_cmd "$c" || missing=1
done
if ! command -v bpftool >/dev/null 2>&1; then
    warn "bpftool not found — required to build kb-core. On Ubuntu: sudo apt install linux-tools-common linux-tools-\$(uname -r)"
    missing=1
fi
if [[ "$missing" -ne 0 ]]; then
    warn "One or more required tools are missing. Install them, then re-run this script."
fi

# ── 2. libbpf (vendored, built in-tree at ./libbpf) ─────────────────────
log "Checking libbpf build (libbpf/src/libbpf.a)"
if [[ -f "libbpf/src/libbpf.a" ]]; then
    echo "libbpf already built — skipping."
elif [[ -d "libbpf/src" ]]; then
    echo "Building vendored libbpf..."
    make -C libbpf/src
else
    warn "libbpf/ directory not present. Clone it before running this script: git clone --branch v1.4.0 https://github.com/libbpf/libbpf.git libbpf"
fi

# ── 3. Python virtual environment + deps (kb-aads) ──────────────────────
log "Setting up kb-aads Python virtual environment"
if [[ ! -d "kb-aads/venv" ]]; then
    python3 -m venv kb-aads/venv
fi
# shellcheck disable=SC1091
source kb-aads/venv/bin/activate
pip install --upgrade pip >/dev/null
pip install -r kb-aads/requirements.txt
deactivate

# ── 4. Go module dependencies (kb-control-plane, kb-op) ─────────────────
log "Downloading Go module dependencies"
(cd kb-control-plane && go mod download)
(cd kb-op/kb-mcp && go mod download 2>/dev/null || true)
(cd kb-op/kbctl && go mod download 2>/dev/null || true)

# ── 5. Node.js dependencies (kb-dashboard) ───────────────────────────────
log "Installing kb-dashboard npm dependencies"
(cd kb-op/kb-dashboard && npm install)

# ── 6. Rust tooling (kb-checker, kb-tui) ─────────────────────────────────
log "Preparing Rust tooling"
rustup show >/dev/null 2>&1 || warn "rustup not detected — ensure a stable Rust toolchain is installed."
(cd kb-checker && cargo fetch)
(cd kb-op/kb-tui && cargo fetch)

log "Install complete. Next: docs/development/full-pipeline-run-guide.md"
