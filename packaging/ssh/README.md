# ssh

The dedicated operator `sshd`: `kb-operator.conf` (installed to `/etc/kb/sshd_kb-operator.conf`, not `sshd_config.d`) and `kb-tui-session-wrapper.sh` (the `ForceCommand` that runs the TUI and reports session start/end to `kbd` for the audit log). Unit: [`../systemd/sshd@kb-operator.service`](../systemd/sshd@kb-operator.service).
