# packaging/vm-test/

Real-host acceptance scripts for the `.deb`, used on the Ubuntu 24.04 demo VM (they need `sudo`;
they prompt for it themselves, run them with a TTY).

| Script | What it does |
| --- | --- |
| `kbinstaller.sh` | Backs up the current install, installs the `.deb` (`--reinstall`, so it also exercises the upgrade path), checks the installer's work, restarts the stack with `kbctl down && kbctl up`, then tests the HTTP API (CORS, token 401/401/200), the dashboard, the SSH operator console (key login, TUI draws, no `[OFFLINE]`), the audit chain and the sensor. Prints PASS/FAIL and a summary. Does not uninstall. |
| `kbuninstaller.sh` | Stops and disables every Kernel Borderlands unit and kills strays so the next run starts from nothing. `--remove-package` also runs `apt remove` so the next install is a fresh one. Never deletes `/etc/kb`, `/var/lib/kbd` or backups. |

```sh
ssh -t kbvm 'bash ~/kbuninstaller.sh --remove-package'   # optional: start from nothing
ssh -t kbvm 'bash ~/kbinstaller.sh'
```

Last full run: 34/34 PASS on Ubuntu 24.04 (see CHANGELOG.md, 2026-10-27). Not covered: `kbagents` under
systemd, reboot persistence, a browser click-through of isolate/restore.
