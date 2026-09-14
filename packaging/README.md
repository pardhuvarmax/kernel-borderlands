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
| `systemd/kb-checker.service` | **Real.** Dependency updated to also require `kb-sensor.service` (auditing bytecode/liveness is meaningless before the sensor has loaded). |
| `systemd/kbagents.service` | **Not yet functional.** `kb-aads` has no compiled-binary build — it runs as `python3 main.py` today. Documents the target convention only. |
| `systemd/kbopd.service` | **Not yet functional.** `kb-op/kb-dashboard` only runs via `npm run dev` today. Documents the target convention only. |
| `systemd/sshd@kb-operator.service` + `ssh/kb-operator.conf` + `ssh/kb-tui-session-wrapper.sh` | **Real** — a second, independent `sshd` instance on port 2222, `ForceCommand`-wrapping `kb-tui`. |

`kbagents`/`kbopd` packaging and giving `kbd` a real `--config` flag are
explicitly deferred to a follow-up pass, not part of this one.

## Installing

```sh
sudo make install                          # builds + installs the 5 real binaries (see top-level Makefile)
sudo scripts/setup/provision.sh            # creates kb group, operator user, /etc/kb, SSH host key
sudo cp packaging/systemd/*.service /etc/systemd/system/
sudo cp packaging/ssh/kb-operator.conf /etc/ssh/sshd_config.d/
sudo install -Dm755 packaging/ssh/kb-tui-session-wrapper.sh /usr/local/bin/kb-tui-session-wrapper.sh
sudo systemctl daemon-reload
sudo systemctl enable --now kbd.service kb-sensor.service kb-checker.service sshd@kb-operator.service
```

`kbagents.service`/`kbopd.service` are intentionally not enabled above —
there is no real binary for either yet.
