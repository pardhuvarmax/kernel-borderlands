# packaging/

Real, installable systemd unit files and SSH config for Kernel Borderlands,
materializing the design in
[docs/architecture/boot_sequence_spec.md](../docs/architecture/boot_sequence_spec.md).
That doc remains the narrative source of truth (boot timeline, race
conditions, tampering containment); this directory is what actually gets
copied onto a host.

## What's real today vs. still aspirational

| Unit | Status |
| --- | --- |
| `systemd/kbd.service` | **Real.** `ExecStart` uses `kbd`'s actual flags (`--db`/`--policy`/`--rules`/`--workloads`) — the spec's `--config /etc/kb/config.yaml` doesn't exist as a flag; see [kb-control-plane/cmd/kbd/main.go](../kb-control-plane/cmd/kbd/main.go). |
| `systemd/kb-sensor.service` | **Real, new in this pass.** Not in the original spec doc at all — added because `kbd_sensor` (`kb-core`, C/eBPF) and `kbd` (Go) are two fully independent OS processes (`kbd` never `exec`s `kbd_sensor`; it just binds `kbd.sock` first so `kbd_sensor` has something to connect to — see `kb-control-plane/internal/ipc/listener.go:134` and `kb-core/userspace/bridge/kb_bridge.c:83`). Without this unit, the eBPF sensor never actually starts under systemd. The spec's own §5 Scenario A already assumed a unit named `kb-sensor.service` existed (it describes stopping it during tampering containment) without ever defining one — this closes that gap under the same name. |
| `systemd/kb-checker.service` | **Real, boot-tested.** Orders after both `kbd.service` and `kb-sensor.service` (auditing bytecode/liveness is meaningless before the sensor has loaded) — but depends on `kb-sensor.service` via `Wants=`, not `Requires=`. `Requires=` was tried first and found, via a real boot test, to make `kb-checker` kill itself: `kb-checker`'s own recovery logic routinely calls `systemctl stop/restart kb-sensor`, and `Requires=`'s stop propagation reacted to that by also stopping `kb-checker.service` itself mid-response, which then misread its own self-inflicted SIGTERM as a failed recovery action and escalated to a full, false Lockdown. `Wants=` keeps the same startup ordering without that propagation. |
| `systemd/kbagents.service` | **Launcher exists, not enabled by default** (see Packages below). Previously: **not yet functional.** `kb-aads` has no compiled-binary build — it runs as `python3 main.py` today. Documents the target convention only. |
| `systemd/kbopd.service` | **Real** (unified `kb-tui` binary serves the embedded dashboard on `127.0.0.1:8082`). Previously: **not yet functional.** `kb-op/kb-dashboard` only runs via `npm run dev` today. Documents the target convention only. |
| `systemd/sshd@kb-operator.service` + `ssh/kb-operator.conf` + `ssh/kb-tui-session-wrapper.sh` | **Real** — a second, independent `sshd` instance on port 2222, `ForceCommand`-wrapping `kb-tui`. |

`kbopd` is now a real, packaged unit (it serves the embedded dashboard). `kbagents` is packaged as a launcher for the Python swarm and is installed but not enabled. Giving `kbd` a real `--config` flag is still not done (`kb.yaml` is not read by any binary).

## Packages (.deb and Arch)

`make install-pkg PREFIX=/usr DESTDIR=<stage>` is the single definition of what ships; both packages wrap it.

| Target | Build on | Command | Output |
| --- | --- | --- | --- |
| Ubuntu / Debian | the target distro (glibc must not be newer than the target's) | `make build && packaging/deb/build-deb.sh` | `dist/kernel-borderlands_0.1.0_amd64.deb` |
| Arch | Arch | `cd packaging/arch && makepkg -f` | `packaging/arch/kernel-borderlands-0.1.0-1-x86_64.pkg.tar.zst` |

Install with `sudo apt install ./kernel-borderlands_*.deb` or `sudo pacman -U kernel-borderlands-*.pkg.tar.zst`. Nothing is started on install: run `sudo kbctl up`, then `kbctl dashboard open` or `kbctl ssh connect`. See `latex/field-manual/` for the full manual.

- **`kb-checker` is under maintenance and repairs and is kept down.** It is never enabled or auto-started: `kbctl up` skips it, `kbctl status` labels it, and `scripts/migrate-legacy.sh` removes any boot autostart on every install/upgrade (and stops it on a fresh install). A manual `systemctl start kb-checker` still works and survives upgrades.
- The operator sshd config ships at `/etc/kb/sshd_kb-operator.conf`, not `/etc/ssh/sshd_config.d/`: that directory is also read by the host's own sshd, which would then bind port 2222 and make `sshd@kb-operator` fail with `Address already in use`. `install.sh` (the dev flow) still uses `sshd_config.d`.
- The dashboard's mutating buttons need `KB_HTTP_API_TOKEN`: install generates it into `/etc/kb/api.env` (root:kb 0640), `kbd.service` loads it, and `kbctl dashboard open` hands it to the browser as a URL fragment. The `operator` account gets `/bin/sh` (a `nologin` shell refuses sshd's `ForceCommand`).
- Package install/upgrade runs `scripts/migrate-legacy.sh` (installed as `/usr/lib/kb/migrate-legacy.sh`): it moves a legacy `/etc/ssh/sshd_config.d/kb-operator.conf` to `/etc/kb/sshd_kb-operator.conf.legacy`, repoints a legacy `/etc/systemd/system/sshd@kb-operator.service`, reloads the host sshd, and restarts `sshd@kb-operator` unless it was stopped by hand. `install.sh` runs it too.
- `kbagents` is a launcher for the Python swarm (`/opt/kb/venv` or system python); it is installed but not enabled.
- Build from a clean `PATH` (system toolchains): a Nix profile's `clang` cannot see `/usr/include/bpf`.

## Real-host testing (Ubuntu VM)

`packaging/vm-test/kbinstaller.sh` installs the `.deb`, restarts the stack and runs 34 checks (installer and migration, API token and CORS, dashboard, services, the SSH console with a live `kbd` link, audit verify, sensor); `kbuninstaller.sh [--remove-package]` stops and disables everything so the next run starts clean. Both need `sudo` and a TTY. Last full run: 34/34 PASS (see `CHANGELOG.md`). The first real-host run found three bugs that were fixed: sshd's empty capability set, the locked `operator` account, and `kba.sock` being `root:root` instead of group `kb`.

## Installing (development flow)


Run the whole thing in one shot:

```sh
./packaging/install.sh
```

This runs (in order): build the 5 real binaries as your own user, `sudo make install`
them to `/usr/local/bin`, `sudo scripts/setup/provision.sh` (kb group, operator user,
`/etc/kb`, SSH host key), install the systemd units + SSH operator-console config,
`daemon-reload`, then `enable --now` `kbd`/`kb-sensor`/`kb-checker`/`sshd@kb-operator`.
It only runs the build step as your own user (so Go/Rust use your existing toolchain
caches, not root's) — everything else shells out to `sudo` individually, so expect a
few password prompts.

Equivalent manual steps, if you'd rather run them one at a time:

```sh
make build && sudo make install            # builds + installs the 5 real binaries (see top-level Makefile)
sudo scripts/setup/provision.sh            # creates kb group, operator user, /etc/kb, SSH host key
sudo cp packaging/systemd/*.service /etc/systemd/system/
sudo cp packaging/ssh/kb-operator.conf /etc/ssh/sshd_config.d/
sudo install -Dm755 packaging/ssh/kb-tui-session-wrapper.sh /usr/local/bin/kb-tui-session-wrapper.sh
sudo systemctl daemon-reload
sudo systemctl enable --now kbd.service kb-sensor.service kb-checker.service sshd@kb-operator.service
```

`kbagents.service`/`kbopd.service` are intentionally not enabled above —
there is no real binary for either yet.

**Before running this on a real host**: confirm your kernel actually has eBPF/LSM
support enabled — see
[docs/architecture/enabling-bpf-lsm.md](../docs/architecture/enabling-bpf-lsm.md).
Everything above has been verified inside a privileged Docker container sharing this
sandbox's kernel (see `CHANGELOG.md`'s boot-test entries) — that proves the systemd
wiring and the daemons' own logic are correct, but it does not prove your specific
target kernel has LSM/BPF enabled.
