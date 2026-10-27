#!/bin/sh
# packaging/scripts/migrate-legacy.sh [fresh|upgrade]
#
# Run by the .deb postinst, the Arch .install hook and packaging/install.sh.
# Idempotent, safe to run on a host with no legacy install (it then does nothing
# but the checker step). Installed as /usr/lib/kb/migrate-legacy.sh.
#
# 1. Legacy operator-sshd repair. The old dev install put the config in
#    /etc/ssh/sshd_config.d/kb-operator.conf, which the HOST's own sshd also
#    includes, so the host sshd bound port 2222 and sshd@kb-operator died with
#    "Address already in use". We move that file out (kept as a backup, never
#    deleted), point a legacy /etc/systemd/system/sshd@kb-operator.service at
#    /etc/kb/sshd_kb-operator.conf, let the host sshd re-read its config, and
#    restart the operator console UNLESS the admin stopped it by hand (it is
#    neither enabled nor active).
#
#    Note: the packaged /etc/kb/sshd_kb-operator.conf is NOT overwritten with the
#    legacy file (its ForceCommand points at the old /usr/local/bin wrapper); the
#    legacy file is preserved beside it as sshd_kb-operator.conf.legacy.
#
# 2. kb-checker stays dead unless started by hand. It is under maintenance and
#    repairs: its boot autostart is removed on every run, and on a fresh install
#    it is also stopped. On an upgrade a running checker is left alone, so a
#    manual `systemctl start kb-checker` survives package upgrades.
set -u

MODE="${1:-upgrade}"
R="${KB_ROOT:-}"          # test hook: relocates every file path under $R
OLD_CONF=$R/etc/ssh/sshd_config.d/kb-operator.conf
NEW_CONF=$R/etc/kb/sshd_kb-operator.conf
OLD_UNIT=$R/etc/systemd/system/sshd@kb-operator.service
OP_UNIT=sshd@kb-operator.service
changed=0
reload_host=0

if [ -f "$OLD_CONF" ]; then
    mkdir -p "$R/etc/kb"
    if [ ! -f "$NEW_CONF" ]; then
        cp -p "$OLD_CONF" "$NEW_CONF"     # dev flow without the new file: never leave the unit without a config
    fi
    mv -f "$OLD_CONF" "$NEW_CONF.legacy"
    echo "kb: moved legacy $OLD_CONF -> $NEW_CONF.legacy (host sshd no longer reads it)"
    changed=1
    reload_host=1
fi

if [ -f "$OLD_UNIT" ] && grep -q '/etc/ssh/sshd_config.d/kb-operator.conf' "$OLD_UNIT"; then
    cp -p "$OLD_UNIT" "$OLD_UNIT.pre-migration"
    sed -i "s#/etc/ssh/sshd_config.d/kb-operator.conf#/etc/kb/sshd_kb-operator.conf#g" "$OLD_UNIT"
    echo "kb: repointed $OLD_UNIT at $NEW_CONF (backup: $OLD_UNIT.pre-migration)"
    changed=1
fi

[ -d /run/systemd/system ] || exit 0
command -v systemctl >/dev/null 2>&1 || exit 0

if [ "$changed" = 1 ]; then
    systemctl daemon-reload || true
    if [ "$reload_host" = 1 ]; then
        # Debian/Ubuntu call the unit ssh, Arch/Fedora sshd. Reload (not restart):
        # existing admin sessions stay up; the listener on 2222 is released.
        for u in ssh sshd; do
            if systemctl is-active --quiet "$u.service" 2>/dev/null; then
                systemctl reload "$u.service" || true
                break
            fi
        done
        sleep 1
    fi
    if systemctl is-enabled --quiet "$OP_UNIT" 2>/dev/null || systemctl is-active --quiet "$OP_UNIT" 2>/dev/null; then
        systemctl restart "$OP_UNIT" || echo "kb: could not restart $OP_UNIT; see journalctl -u sshd@kb-operator"
    else
        echo "kb: $OP_UNIT is stopped and disabled; leaving it that way (start with: kbctl ssh up)"
    fi
fi

systemctl disable kb-checker.service >/dev/null 2>&1 || true
if [ "$MODE" = fresh ]; then
    systemctl stop kb-checker.service >/dev/null 2>&1 || true
fi
exit 0
