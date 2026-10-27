#!/bin/sh
# packaging/scripts/migrate-legacy.sh [fresh|upgrade]
#
# Run by the .deb postinst, the Arch .install hook and packaging/install.sh.
# Installed as /usr/lib/kb/migrate-legacy.sh. Idempotent; on a clean host it only
# ensures the API token and the checker's "stays dead" state.
#
# 1. Dashboard API token. kbd's mutating HTTP routes (isolate/restore/policy-reload)
#    fail closed without KB_HTTP_API_TOKEN. We generate a random token once into
#    /etc/kb/api.env (root:kb 0640, never overwritten); kbd.service loads it through
#    EnvironmentFile and `kbctl dashboard open` hands it to the browser as a URL
#    fragment. kbd must be restarted to pick up a NEW token (we print a notice; we
#    do not restart kbd/the sensor behind your back).
#
# 2. operator login shell. sshd runs a ForceCommand as "$SHELL -c <cmd>", which a
#    nologin/false shell refuses. An existing operator account with such a shell is
#    switched to /bin/sh (the operator sshd config already forces the wrapper, is
#    key-only and forbids forwarding).
#
# 3. Legacy dev install. The old install put the operator sshd config in
#    /etc/ssh/sshd_config.d/ (the HOST's sshd includes that directory, bound port 2222
#    itself, and sshd@kb-operator died with "Address already in use") and units in
#    /etc/systemd/system that override the packaged ones. We move the conf to
#    /etc/kb/sshd_kb-operator.conf.legacy (the packaged conf is NOT overwritten: its
#    ForceCommand points at the packaged wrapper), move legacy dev units aside as
#    *.pre-migration so the packaged units apply, daemon-reload, reload the host sshd
#    (releases port 2222) and restart sshd@kb-operator UNLESS it was stopped by hand
#    (neither enabled nor active). Other migrated units that are running are not
#    restarted; a notice says so.
#
# 4. kb-checker stays dead unless started by hand. It is under maintenance and repairs:
#    its boot autostart is removed on every run, and on a fresh install it is also
#    stopped. On an upgrade a running checker is left alone, so a manual
#    `systemctl start kb-checker` survives package upgrades.
set -u

MODE="${1:-upgrade}"
R="${KB_ROOT:-}"          # test hook: relocates every file path under $R
OLD_CONF=$R/etc/ssh/sshd_config.d/kb-operator.conf
NEW_CONF=$R/etc/kb/sshd_kb-operator.conf
API_ENV=$R/etc/kb/api.env
UNIT_DIR=$R/etc/systemd/system
OP_UNIT=sshd@kb-operator.service
changed=0
reload_host=0
need_restart=""

# ---- 1. API token -------------------------------------------------------------
if [ ! -s "$API_ENV" ]; then
    mkdir -p "$R/etc/kb"
    tok=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    ( umask 077; printf 'KB_HTTP_API_TOKEN=%s\n' "$tok" > "$API_ENV" )
    chgrp kb "$API_ENV" 2>/dev/null || true
    chmod 0640 "$API_ENV"
    echo "kb: generated the dashboard API token in /etc/kb/api.env"
    need_restart="$need_restart kbd.service"
fi

# ---- 2. operator shell (real hosts only) ----------------------------------------
if [ -z "$R" ] && command -v getent >/dev/null 2>&1; then
    op_shell=$(getent passwd operator | cut -d: -f7)
    case "$op_shell" in
        */nologin|*/false)
            if usermod -s /bin/sh operator 2>/dev/null; then
                echo "kb: operator shell $op_shell -> /bin/sh (sshd ForceCommand needs a real shell)"
            fi ;;
    esac
fi

# ---- 3. legacy dev install -------------------------------------------------------
if [ -f "$OLD_CONF" ]; then
    mkdir -p "$R/etc/kb"
    [ -f "$NEW_CONF" ] || cp -p "$OLD_CONF" "$NEW_CONF"   # never leave the unit without a config
    mv -f "$OLD_CONF" "$NEW_CONF.legacy"
    echo "kb: moved legacy /etc/ssh/sshd_config.d/kb-operator.conf -> /etc/kb/sshd_kb-operator.conf.legacy"
    changed=1; reload_host=1
fi

for u in kbd kb-sensor kb-checker kbopd kbagents sshd@kb-operator; do
    f=$UNIT_DIR/$u.service
    [ -f "$f" ] || continue
    if grep -q -E '/usr/local/bin|sshd_config\.d/kb-operator\.conf' "$f"; then
        mv -f "$f" "$f.pre-migration"
        echo "kb: legacy dev unit $u.service moved aside ($f.pre-migration); the packaged unit now applies"
        changed=1
        if [ "$u" != sshd@kb-operator ]; then need_restart="$need_restart $u.service"; fi
    fi
done

have_systemd=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then have_systemd=1; fi

if [ "$have_systemd" = 1 ]; then
    if [ "$changed" = 1 ]; then
        systemctl daemon-reload || true
        if [ "$reload_host" = 1 ]; then
            # Debian/Ubuntu: ssh.service, Arch/Fedora: sshd.service. Reload, not restart:
            # admin sessions stay up; the listener on 2222 is released.
            for h in ssh sshd; do
                if systemctl is-active --quiet "$h.service" 2>/dev/null; then
                    systemctl reload "$h.service" || true
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
    # Running core units keep their old code/environment until restarted.
    running=""
    for u in $need_restart; do
        case " $running " in *" ${u%.service} "*) continue ;; esac
        systemctl is-active --quiet "$u" 2>/dev/null && running="$running ${u%.service}"
    done
    if [ -n "$running" ]; then
        echo "kb: restart to apply the new unit/token:$running   (sudo kbctl down && sudo kbctl up)"
    fi

    # ---- 4. kb-checker -------------------------------------------------------------
    systemctl disable kb-checker.service >/dev/null 2>&1 || true
    if [ "$MODE" = fresh ]; then
        systemctl stop kb-checker.service >/dev/null 2>&1 || true
    fi
fi
exit 0
