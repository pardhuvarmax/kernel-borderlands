# Full Pipeline Run Guide (Core → Control Plane → AADS → Ops)

Manual, step-by-step guide to bring up the Kernel Borderlands stack end-to-end on a single dev host: `kb-core` → `kb-control-plane` → `kb-aads` → `kb-op`. **`kb-checker` is intentionally excluded** — the stack below runs without the safety watchdog, unlike the production boot sequence in [boot_sequence_spec.md](../architecture/boot_sequence_spec.md), which gates AADS startup on `kb-checker` passing. Do not use this ordering as a production reference; use it for local development/demo runs only.

Sources consulted: [developer-commands.md](developer-commands.md), [../architecture/boot_sequence_spec.md](../architecture/boot_sequence_spec.md), [../getting-started/installation.md](../getting-started/installation.md), `kb-core/README.md`, `kb-control-plane/README.md`, `kb-op/README.md` and subsystem READMEs, `config/README.md`.

---

## 0. Why this order

Unlike systemd's boot sequence, `kb-control-plane` (not `kb-core`) owns `/run/kb/` and creates all three of its sockets on startup. `kb-core`'s sensor is a *client* of those sockets — it has no socket-creation or config-discovery logic of its own. `kb-aads` and every `kb-op` interface are gRPC clients of `kba.sock`. So the only safe manual order is:

```
kb-control-plane (kbd)  →  kb-core (kbd_sensor)  →  kb-aads  →  kb-op (tui / dashboard / mcp / kbctl)
```

Starting `kb-core` before `kbd` will fail to connect (`kbd.sock`/`kbct.sock` don't exist yet). Starting `kb-aads` or `kb-op` before `kbd` will fail to connect to `kba.sock`.

---

## 1. Prerequisites

| Component  | Version |
| ---------- | ------- |
| Git        | Latest  |
| Python     | 3.11+ (repo venv observed at 3.12) |
| Go         | 1.23+   |
| Node.js    | 20+     |
| Clang/LLVM | 18+     |
| Make       | Latest  |
| bpftool, libelf, libz | latest (kb-core) |

Additional for `kb-core`: BPF LSM enabled in the kernel command line (`lsm=...,bpf` in GRUB) — see [enabling-bpf-lsm.md](../architecture/enabling-bpf-lsm.md).

**Note:** [installation.md](../getting-started/installation.md) references `scripts/setup/install.sh` as the "Automatic Installation" method. That script **does not exist in the repo** (`scripts/setup/` contains only a README). Use the manual per-subsystem install steps below instead.

### 1.1 Manual dependency install

```bash
# libbpf (vendored, no example/build script present — see kb-core/README.md
# and libbpf/ directory; build per that subsystem's own instructions)

# kb-control-plane (Go)
cd kb-control-plane && go mod download && cd ..

# kb-aads (Python)
cd kb-aads
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ..

# kb-op/kb-dashboard (Node)
cd kb-op/kb-dashboard && npm install && cd ../..

# kb-op/kb-tui (Rust)
cd kb-op/kb-tui && cargo build --release && cd ../..

# kb-op/kb-mcp, kbctl (Go)
cd kb-op/kb-mcp && go build -o kb-mcp main.go && cd ../..
cd kb-op/kbctl && go build -o kbctl main.go && cd ../..
```

---

## 2. Config gap — read before running

`config/README.md` documents five files: `kb.yaml`, `policy.yaml`, `allowlist.yaml`, `agents.yaml`, `dashboard.yaml`, and says to "copy `*.yaml.example` to `*.yaml`". As of this writing, **only `policy.yaml` and `agents.yaml` actually exist**; there are no `.yaml.example` files anywhere in the repo, and `kb.yaml`, `allowlist.yaml`, `dashboard.yaml` are absent. This run guide only exercises the two files that exist. If a task needs the other three, treat them as undocumented/to-be-created — don't assume defaults.

- `config/policy.yaml` — enforcement thresholds, per-process policy overrides, additive sensitive paths. Consumed by `kbd` via `--policy`.
- `config/agents.yaml` — AADS swarm composition, Ray mode, `control_plane.grpc_socket`. Consumed by `kb-aads/main.py` (hardcoded relative path `../config/agents.yaml`, no env override).

---

## 3. Step 1 — Build everything

```bash
# kb-core
cd kb-core && make && cd ..

# kb-control-plane
cd kb-control-plane && go build -o bin/kbd cmd/kbd/main.go && cd ..
# (kb-control-plane/README.md instead shows `go build -o kbd cmd/kbd/main.go`
#  from inside kb-control-plane/ — either output path works, just be
#  consistent about where you invoke the binary from below.)

# kb-op
cd kb-op/kb-tui && cargo build --release && cd ../..
cd kb-op/kb-mcp && go build -o kb-mcp main.go && cd ../..
cd kb-op/kbctl && go build -o kbctl main.go && cd ../..
```

`kb-aads` and `kb-dashboard` are not compiled ahead of time — run directly (Python) or via dev server (Vite).

---

## 4. Step 2 — Run `kb-control-plane` (`kbd`) first

```bash
cd kb-control-plane
./bin/kbd --db data/state.db --policy ../config/policy.yaml
```

Flags (cobra, `cmd/kbd/main.go`):
- `--db` / `-d` — SQLite state DB path (default `/var/lib/kbd/state.db`)
- `--policy` / `-p` — policy YAML path (default `config/policy.yaml`, relative to CWD)

On startup `kbd`:
- Creates `/run/kb/` and binds `kbd.sock`, `kbct.sock`, `kba.sock` (root:root, 0660) — you likely need `sudo` for this on a real `/run`, or point at a writable alternate runtime dir if the code supports it.
- Starts the SSH console service (host key `/etc/kb/ssh_host_ed25519_key`, `authorized_keys` at `/etc/kb/authorized_keys`, with a workspace-local dev fallback + warning if those paths are missing).

**Verify before continuing:**
```bash
ls -l /run/kb/
# expect kbd.sock, kbct.sock, kba.sock
```

---

## 5. Step 3 — Run `kb-core` sensor

```bash
cd kb-core
sudo ./build/kbd_sensor
```

Root required to load eBPF/LSM hooks. No CLI flags or config file of its own — it dials `kbd.sock` / `kbct.sock`, which must already exist (Step 2). If BPF LSM isn't enabled in the kernel command line, hook attachment will fail — see [enabling-bpf-lsm.md](../architecture/enabling-bpf-lsm.md).

**Verify:** telemetry should start flowing into `kbd`'s logs/state; `kbd_sensor` process stays foregrounded.

---

## 6. Step 4 — Run `kb-aads` (agent swarm)

```bash
cd kb-aads
source venv/bin/activate
python main.py
```

Reads `../config/agents.yaml` relative to `kb-aads/` (hardcoded, no env override). Defaults: `ray.mode: local` (single-node in-process Ray head — no external Ray cluster needed for dev), `control_plane.grpc_socket: /run/kb/kba.sock`. Must be started after `kbd` (Step 2) so `kba.sock` exists.

---

## 7. Step 5 — Run `kb-op` interfaces

Any/all of these can run concurrently once `kbd` is up; none depend on `kb-aads`.

### 7.1 `kb-tui`
```bash
cd kb-op/kb-tui
cargo run
```
Connects directly to `/run/kb/kba.sock`. Falls back to an offline/demo mode (clearly bannered) with synthetic data if the socket is unreachable — useful to sanity-check the binary independent of `kbd`. In production this binary isn't run standalone — `kbd`'s own SSH service spawns it per-session (`ssh operator@localhost -p 2222`); don't expect both entry paths to represent separate live sessions of the same state.

### 7.2 `kb-dashboard`
```bash
cd kb-op/kb-dashboard
npm run dev
# http://localhost:5173
```
**Gap:** no `.env`/`VITE_*` variable or config found in the repo for the dashboard's API/WebSocket target — `vite.config.ts` is default/unmodified. The dashboard's connection to `kbd` is not documented or configurable at this time; treat it as unverified/stubbed until the wiring is confirmed in source.

### 7.3 `kb-mcp`
```bash
cd kb-op/kb-mcp
./kb-mcp
```
JSON-RPC 2.0 over stdio (no port) — bridges to `kbd` over gRPC/UDS and to `kb-core` native components. Intended for AI client integration, not direct human interaction.

### 7.4 `kbctl`
```bash
cd kb-op/kbctl
./kbctl policy reload
./kbctl stats
```
Talks gRPC over `kba.sock`, same channel as `kb-tui`/`kb-mcp`.

---

## 8. Full run order — copy/paste summary

```bash
# Terminal 1 — control plane (start first, owns /run/kb/*)
cd kb-control-plane && ./bin/kbd --db data/state.db --policy ../config/policy.yaml

# Terminal 2 — sensor (after /run/kb/*.sock exist)
cd kb-core && sudo ./build/kbd_sensor

# Terminal 3 — agent swarm
cd kb-aads && source venv/bin/activate && python main.py

# Terminal 4 — TUI (optional)
cd kb-op/kb-tui && cargo run

# Terminal 5 — dashboard (optional)
cd kb-op/kb-dashboard && npm run dev

# Terminal 6 — MCP server (optional)
cd kb-op/kb-mcp && ./kb-mcp

# Ad hoc — CLI ops
cd kb-op/kbctl && ./kbctl stats
```

`kb-checker` is deliberately omitted — see the note at the top. Reintroducing it later means inserting it between Steps 3 and 4 per [boot_sequence_spec.md](../architecture/boot_sequence_spec.md) Phase 2/3, and its `Requires=kb-checker.service` gate on the AADS agent would need a manual equivalent (nothing currently enforces that dependency outside systemd).

---

## 9. Known documentation gaps / inconsistencies found while writing this guide

- `scripts/setup/install.sh`, referenced by [installation.md](../getting-started/installation.md), does not exist — `scripts/setup/` has only a README.
- `config/README.md` documents `kb.yaml`, `allowlist.yaml`, `dashboard.yaml` and a `*.yaml.example` copy step; none of the examples exist, and only `policy.yaml`/`agents.yaml` are present.
- `kb-control-plane` build command differs between `CLAUDE.md`/[developer-commands.md](developer-commands.md) (`go build -o bin/kbd cmd/kbd/main.go`) and `kb-control-plane/README.md` (`go build -o kbd cmd/kbd/main.go`, run from inside the subdirectory). Functionally equivalent, just pick one path convention and stay consistent.
- `kb-op/README.md`'s architecture diagram labels the gRPC gateway "Port 50051," but every subsystem README (`kb-tui`, `kbctl`, `kb-mcp`) describes the actual transport as the UDS `kba.sock`, not a TCP port. Treat "50051" as a stale/illustrative diagram artifact, not a real bound port, until contradicted by source.
- `kb-dashboard`'s connection to `kbd` (API base URL / WS endpoint) has no discoverable config in the repo — flagged above, not fixed here.

Fix or confirm these before treating this guide as authoritative for onboarding new contributors.
