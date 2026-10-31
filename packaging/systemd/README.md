# systemd

The units, written for the dev install paths (`/usr/local/bin`) and rewritten to `/usr/bin` by `make install-pkg`.

| Unit | Runs |
| --- | --- |
| `kbd.service` | The control plane (`Type=notify`) |
| `kb-sensor.service` | The eBPF sensor; restarts bounded to 5 per 120 s, journal rate-limited |
| `kbopd.service` | The operator console and embedded dashboard |
| `sshd@kb-operator.service` | The operator SSH entry point |
| `kbagents.service` | The agent swarm |
| `kb-checker.service` | The watchdog; **only starts if `/etc/kb/checker.enabled` exists** (kept down under maintenance) |

Boot order and socket topology: [`../../docs/architecture/boot_sequence_spec.md`](../../docs/architecture/boot_sequence_spec.md).
