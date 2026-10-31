# scripts

`migrate-legacy.sh`: repairs a host that has an older dev install (for example the operator `sshd` config in `/etc/ssh/sshd_config.d/`, which made the host's own `sshd` bind port 2222). Run by the package's post-install step.
