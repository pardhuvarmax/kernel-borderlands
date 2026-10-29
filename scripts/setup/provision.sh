#!/bin/sh
# scripts/setup/provision.sh
#
# Host provisioning for Kernel Borderlands: creates the `kb` group, the
# `operator` system user, /etc/kb, and the SSH host key used by
# sshd@kb-operator.service — none of which any other script in this repo
# creates today. scripts/setup/install.sh explicitly disclaims this exact
# scope ("does NOT... create /run/kb, or touch /etc/kb") — this is the
# script that closes that gap.
#
# Idempotent: safe to re-run. Requires root. Deliberately does NOT touch
# /run/kb (owned by kbd.service's RuntimeDirectory=kb, created/cleaned by
# systemd itself) or /etc/kb/ebpf_policies.json (kb-checker generates a
# default template on first run if missing — see
# kb-checker/src/integrity/mod.rs:21,41).
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "provisioning must be run as root" >&2
    exit 1
fi

if ! getent group kb >/dev/null 2>&1; then
    groupadd --system kb
    echo "created group: kb"
else
    echo "group kb already exists, skipping"
fi

if ! getent passwd operator >/dev/null 2>&1; then
    # Shell is /bin/sh, not nologin: sshd runs a ForceCommand as "$SHELL -c <cmd>", which a
    # nologin shell refuses ("This account is currently not available"). The account stays
    # locked down by the operator sshd config: key-only, ForceCommand wrapper, no forwarding,
    # no password.
    # Home is / (not /home/operator): the account has no home, sshd chdirs to it on every login
    # and warns "Could not chdir to home directory" because the unit hides /home (ProtectHome).
    useradd --system --no-create-home --home-dir / --shell /bin/sh --gid kb operator
    # useradd leaves the shadow password as "!" (locked). With UsePAM no (our standalone sshd
    # config) OpenSSH refuses a locked account even for public-key logins ("User operator not
    # allowed because account is locked"). "*" = no usable password, but not locked.
    usermod -p '*' operator
    echo "created user: operator (member of kb)"
else
    echo "user operator already exists, skipping"
fi

mkdir -p /etc/kb
mkdir -p /etc/kb/ssh
chown root:kb /etc/kb
chmod 0750 /etc/kb

HOST_KEY=/etc/kb/ssh/ssh_host_ed25519_key
if [ ! -f "$HOST_KEY" ]; then
    ssh-keygen -t ed25519 -f "$HOST_KEY" -N ""
    echo "generated SSH host key: $HOST_KEY"
else
    echo "SSH host key already exists, skipping: $HOST_KEY"
fi

AUTH_KEYS=/etc/kb/authorized_keys
if [ ! -f "$AUTH_KEYS" ]; then
    touch "$AUTH_KEYS"
    chown operator:kb "$AUTH_KEYS"
    chmod 0600 "$AUTH_KEYS"
    echo "created empty $AUTH_KEYS — add operator public keys here"
else
    echo "$AUTH_KEYS already exists, skipping"
fi

echo "provisioning complete"
