#!/bin/bash
# kbinstaller.sh — installs the kernel-borderlands .deb on THIS host and checks it end to end.
# Run with a TTY so sudo can prompt once:  ssh -t kbvm 'bash ~/kbinstaller.sh'
# Backs up the legacy dev install first. Does not uninstall anything.
DEB=${DEB:-$HOME/kb-pkg-build/dist/kernel-borderlands_1.1.0_amd64.deb}
TS=$(date +%Y%m%d-%H%M%S); BK=$HOME/kb-backup-$TS; LOG=$HOME/kb-test-$TS.log
PASS=0; FAIL=0; FAILS=()
exec > >(tee -a "$LOG") 2>&1
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); FAILS+=("$*"); }
chk() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
sec() { echo; echo "=== $* ==="; }
K=/usr/bin/kbctl

sudo -v || { echo "sudo failed"; exit 1; }
( while true; do sudo -n true; sleep 50; kill -0 $$ 2>/dev/null || exit; done ) 2>/dev/null &

sec "0. Preconditions and backup"
[ -f "$DEB" ] && ok "deb present: $DEB" || { bad "deb missing"; exit 1; }
sha256sum "$DEB"
mkdir -p "$BK"
sudo cp -a /etc/systemd/system/kb*.service /etc/systemd/system/sshd@kb-operator.service "$BK"/ 2>/dev/null
sudo cp -a /etc/ssh/sshd_config.d/kb-operator.conf "$BK"/ 2>/dev/null
sudo cp -a /etc/kb "$BK"/etc-kb 2>/dev/null
echo "backup in $BK"; ls "$BK"
echo "--- state BEFORE:"
for u in kbd kb-sensor kb-checker kbopd sshd@kb-operator; do printf "  %-22s %s\n" $u "$(systemctl is-active $u 2>&1)"; done
ss -ltn 2>/dev/null | grep -E ':(8080|8082|2222)\b' | sed 's/^/  /'

sec "1. Install the package"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall "$DEB" 2>&1 | tail -25
echo "apt exit: ${PIPESTATUS[0]}"
chk "dpkg reports installed" bash -c 'dpkg -s kernel-borderlands | grep -q "Status: install ok installed"'

sec "2. What the installer did"
chk "operator account not locked (shadow is not '!...')" bash -c '! sudo getent shadow operator | cut -d: -f2 | grep -q "^!"'
chk "operator home is / (no chdir warning)" bash -c 'getent passwd operator | cut -d: -f6 | grep -qx /'
chk "operator shell is /bin/sh (not nologin)" bash -c 'getent passwd operator | grep -q ":/bin/sh$"'
chk "api.env exists, 640 root:kb" bash -c '[ "$(sudo stat -c "%a %U:%G" /etc/kb/api.env)" = "640 root:kb" ]'
chk "api.env holds a 64-hex token" bash -c 'sudo grep -Eq "^KB_HTTP_API_TOKEN=[0-9a-f]{64}$" /etc/kb/api.env'
chk "legacy sshd_config.d conf moved away" bash -c '[ ! -e /etc/ssh/sshd_config.d/kb-operator.conf ]'
chk "legacy conf kept as backup (.legacy)" sudo test -e /etc/kb/sshd_kb-operator.conf.legacy
chk "no legacy dev units left in /etc/systemd/system" bash -c '! ls /etc/systemd/system/kb*.service /etc/systemd/system/sshd@kb-operator.service 2>/dev/null | grep -q .'
chk "packaged units resolve to /usr/lib" bash -c 'systemctl cat kbd.service | head -1 | grep -q /usr/lib/systemd/system'
chk "kbd unit loads api.env" bash -c 'systemctl cat kbd.service | grep -q "EnvironmentFile=-/etc/kb/api.env"'
chk "kb-checker NOT enabled" bash -c '! systemctl is-enabled --quiet kb-checker'
chk "kb-checker NOT running" bash -c '! systemctl is-active --quiet kb-checker'
ls /etc/systemd/system/*.pre-migration 2>/dev/null | sed 's/^/  migrated aside: /'

sec "3. Restart the stack on the packaged units"
sudo $K down; sleep 2; sudo $K up; sleep 6
$K status
for u in kbd kb-sensor kbopd sshd@kb-operator; do
  chk "$u active" systemctl is-active --quiet $u
done
chk "kb-checker still dead after 'kbctl up'" bash -c '! systemctl is-active --quiet kb-checker'
$K status | tail -1 | grep -q 'UNDER MAINTENANCE' && ok "status shows maintenance label" || bad "status maintenance label"
chk "port 2222 held by the operator sshd, not the host sshd" bash -c 'systemctl is-active --quiet sshd@kb-operator && sudo ss -ltnp | grep ":2222 " | grep -q sshd'
chk "kba.sock group is kb" bash -c '[ "$(stat -c %G /run/kb/kba.sock 2>/dev/null)" = kb ]'

sec "4. kbd HTTP API, CORS and token"
TOK=$(sudo grep -E '^KB_HTTP_API_TOKEN=' /etc/kb/api.env | cut -d= -f2)
H=$(curl -si -m 5 -H 'Origin: http://127.0.0.1:8082' http://127.0.0.1:8080/api/services)
echo "$H" | head -1
echo "$H" | grep -qi 'access-control-allow-origin: http://127.0.0.1:8082' && ok "CORS allows the dashboard origin" || bad "CORS allows dashboard origin"
curl -si -m 5 -H 'Origin: http://evil.example' http://127.0.0.1:8080/api/services | grep -qi 'access-control-allow-origin' && bad "CORS leaks to foreign origin" || ok "CORS blocks foreign origin"
c1=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST http://127.0.0.1:8080/api/policy/reload)
c2=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST -H "Authorization: Bearer wrong" http://127.0.0.1:8080/api/policy/reload)
c3=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST -H "Authorization: Bearer $TOK" http://127.0.0.1:8080/api/policy/reload)
echo "  policy/reload: no token=$c1  wrong token=$c2  right token=$c3"
[ "$c1" = 401 ] && ok "no token -> 401" || bad "no token expected 401 got $c1"
[ "$c2" = 401 ] && ok "wrong token -> 401" || bad "wrong token expected 401 got $c2"
[ "$c3" = 200 ] && ok "right token -> 200 (policy reloaded)" || bad "right token expected 200 got $c3"

sec "5. Dashboard"
c=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1:8082/); [ "$c" = 200 ] && ok "dashboard serves (200)" || bad "dashboard got $c"
$K dashboard status && ok "kbctl dashboard status" || bad "kbctl dashboard status"
echo "  tokened URL form: $($K dashboard url --token | sed -E 's/(token=).{8}.*/\1<redacted>/')"

sec "6. SSH operator console (key auth, ForceCommand, PTY)"
KD=$(mktemp -d); ssh-keygen -q -t ed25519 -N '' -f $KD/k
sudo $K ssh add-key $KD/k.pub
out=$( ( sleep 5; printf '\t'; sleep 1.5; printf 'q'; sleep 2 ) | timeout 30 script -qec "stty rows 40 cols 140; ssh -tt -p 2222 -i $KD/k -o BatchMode=yes -o PasswordAuthentication=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR operator@127.0.0.1" /dev/null 2>&1 | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' | tr -d '\r' | strings -n 5 )
echo "$out" | grep -E 'Processes|Alerts|Agent Activity|Query Console|OFFLINE|not available' | sort -u | head -6 | sed 's/^/  | /'
echo "--- raw session output (first 25 lines):"; echo "$out" | head -25 | cut -c1-160 | sed 's/^/  > /'
echo "--- sshd@kb-operator journal (last 12):"; sudo journalctl -u sshd@kb-operator -n 12 --no-pager 2>&1 | cut -c1-190 | sed 's/^/  | /'
echo "$out" | grep -q 'Permission denied (publickey' && bad "publickey auth rejected (see journal above)"
echo "$out" | grep -q 'not available' && bad "nologin refused ForceCommand" || ok "no 'account not available' refusal"
echo "$out" | grep -q -E 'Processes|Alerts' && ok "TUI rendered over SSH" || bad "TUI did not render over SSH"
echo "$out" | grep -q 'OFFLINE' && bad "TUI says kbd OFFLINE" || ok "TUI connected to kbd (not offline)"
echo "$out" | grep -q 'chdir to home' && bad "home chdir warning still shown" || ok "no home-directory warning"
echo "$out" | grep -q 'audit logging failed' && bad "session audit callback failed" || ok "session audit callback reached kbd"
KEYLINE=$(cut -d' ' -f1-2 $KD/k.pub); sudo sed -i "\#$KEYLINE#d" /etc/kb/authorized_keys; rm -rf $KD
echo "  (temporary test key removed from /etc/kb/authorized_keys)"
sudo $K audit verify 2>&1 | sed 's/^/  /'

sec "7. Sensor"
sudo journalctl -u kb-sensor -n 15 --no-pager 2>&1 | cut -c1-170 | sed 's/^/  /'
sudo journalctl -u kbd -n 6 --no-pager 2>&1 | cut -c1-170 | sed 's/^/  /'

sec "SUMMARY"
echo "PASS=$PASS FAIL=$FAIL   (log: $LOG, backup: $BK)"
[ $FAIL -gt 0 ] && { printf '  FAILED: %s\n' "${FAILS[@]}"; }
echo "Not covered: kbagents under systemd, reboot persistence, browser click-through of isolate/restore."
echo "Undo: sudo apt remove kernel-borderlands   (legacy units are saved as *.pre-migration; full backup in $BK)"
