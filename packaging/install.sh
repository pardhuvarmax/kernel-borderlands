#!/bin/sh
# packaging/install.sh — single entry point that runs everything documented
# in packaging/README.md's "Installing" section, in order:
#   1. build the 5 real binaries (as the invoking user, not root)
#   2. install them to /usr/local/bin (sudo)
#   3. provision the host: kb group, operator user, /etc/kb, SSH host key (sudo)
#   4. install the real systemd units + SSH operator-console config (sudo)
#   5. daemon-reload, then enable+start the real, working units
#
# Deliberately does NOT run the whole script as root — `make build`
# (Go/Rust/C compilation) runs as the invoking user, so it uses that
# user's own toolchain caches (~/.cargo, GOPATH, etc.) instead of
# re-fetching everything under root's HOME. Only the steps that actually
# need root (installing into /usr/local, provisioning system
# users/groups, writing systemd units) shell out to sudo individually —
# expect a few password prompts.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "== [1/5] Building kb-core, kbd, kb-checker, kbctl, kb-tui =="
make build

echo "== [2/5] Installing binaries to /usr/local/bin =="
sudo make install

echo "== [3/5] Provisioning host (kb group, operator user, /etc/kb, SSH host key) =="
sudo scripts/setup/provision.sh

echo "== [4/5] Installing systemd units and SSH operator-console config =="
sudo cp packaging/systemd/*.service /etc/systemd/system/
# NOT /etc/ssh/sshd_config.d/: the host's own sshd includes that directory and would bind
# the config's `Port 2222` itself, so sshd@kb-operator would die with "Address already in use".
sudo install -Dm644 packaging/ssh/kb-operator.conf /etc/kb/sshd_kb-operator.conf
sudo install -Dm755 packaging/ssh/kb-tui-session-wrapper.sh /usr/local/bin/kb-tui-session-wrapper.sh
sudo systemctl daemon-reload

# kb-checker is deliberately not started: under maintenance and repairs.
# FIX: Added kbopd.service to the active boot list below
echo "== [5/5] Enabling and starting kbd, kb-sensor, sshd@kb-operator, kbopd (kb-checker: under maintenance, kept down) =="
sudo systemctl enable --now kbd.service kb-sensor.service sshd@kb-operator.service kbopd.service

echo
echo "Done. All core systems and the unified Operator Dashboard are running!"
echo
# FIX: Added kbopd.service status output
sudo systemctl --no-pager status kbd.service kb-sensor.service kbopd.service

