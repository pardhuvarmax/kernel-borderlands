#!/bin/bash
# kbuninstaller.sh — stop and disable every Kernel Borderlands service on THIS host so the
# next test starts from nothing running. Run with a TTY:  ssh -t kbvm 'bash ~/kbuninstaller.sh'
#   --remove-package   also `apt remove kernel-borderlands`, so the next install is a FRESH one
# Never deletes data: /etc/kb (keys, token, config), /var/lib/kbd (state, audit chain), backups stay.
REMOVE=0; [ "${1:-}" = "--remove-package" ] && REMOVE=1
UNITS=(sshd@kb-operator kbopd kbagents kb-checker kb-sensor kbd)   # reverse boot order

sudo -v || { echo "sudo failed"; exit 1; }
echo "=== BEFORE ==="
for u in "${UNITS[@]}"; do printf "  %-18s active=%-12s enabled=%s\n" $u "$(systemctl is-active $u 2>&1)" "$(systemctl is-enabled $u 2>&1)"; done
ss -ltn 2>/dev/null | grep -E ':(8080|8082|8601|2222)\b' | sed 's/^/  listening: /'

echo; echo "=== stopping and disabling (reverse boot order) ==="
for u in "${UNITS[@]}"; do
  sudo systemctl disable --now "$u.service" 2>&1 | grep -v -E '^(Removed|Synchronizing|Executing)' | sed "s/^/  $u: /"
  sudo systemctl reset-failed "$u.service" 2>/dev/null
done

echo; echo "=== stray processes (should be none) ==="
sleep 2
left=$(pgrep -a -x -f '.*(kbd_sensor|/kbd |kbopd|mcp-server|kb-checker|kbagents).*' 2>/dev/null | grep -v -E 'pgrep|kbuninstaller' )
if [ -n "$left" ]; then
  echo "$left" | cut -c1-140 | sed 's/^/  /'
  echo "  -> terminating (SIGTERM, then SIGKILL after 3s)"
  for p in kbd_sensor kbopd mcp-server kb-checker kbagents; do sudo pkill -x "$p" 2>/dev/null; done
  sudo pkill -f '^/usr/bin/kbd( |$)' 2>/dev/null
  sleep 3
  for p in kbd_sensor kbopd mcp-server kb-checker kbagents; do sudo pkill -9 -x "$p" 2>/dev/null; done
else
  echo "  none"
fi
pgrep -fa 'kbagents|aads|ray::|raylet|gcs_server' 2>/dev/null | grep -v -E 'pgrep|cleanup' | cut -c1-120 | sed 's/^/  swarm leftover: /'

if [ $REMOVE = 1 ]; then
  echo; echo "=== removing the package (config, keys, token and state are kept) ==="
  sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y kernel-borderlands 2>&1 | tail -4
  dpkg -s kernel-borderlands 2>&1 | head -1
fi

echo; echo "=== AFTER ==="
for u in "${UNITS[@]}"; do printf "  %-18s active=%-12s enabled=%s\n" $u "$(systemctl is-active $u 2>&1)" "$(systemctl is-enabled $u 2>&1)"; done
l=$(ss -ltn 2>/dev/null | grep -E ':(8080|8082|8601|2222)\b')
[ -z "$l" ] && echo "  ports 8080/8082/8601/2222: all free" || echo "$l" | sed 's/^/  STILL LISTENING: /'
pgrep -x -f '.*(kbd_sensor|kbopd|mcp-server|kb-checker).*' >/dev/null 2>&1 && echo "  WARNING: kb processes still running" || echo "  no kb processes running"
echo; echo "Kept: /etc/kb /var/lib/kbd and the backups in ~/kb-backup-*. Now run:  ssh -t kbvm 'bash ~/kbinstaller.sh'"
