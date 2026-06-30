#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# KB Core — Hook Verification Test Script
# Triggers all 9 event types one at a time with labels,
# so output can be matched against kbd_sensor's live stream.
#
# Usage:
#   Terminal 1: sudo ./build/kbd_sensor
#   Terminal 2: ./scripts/test_all_hooks.sh
# ═══════════════════════════════════════════════════════════

set -uo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

pause() {
    sleep 1.5
}

section() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
}

ok() {
    echo -e "${GREEN}  ✓ Triggered: $1${NC}"
}

echo -e "${YELLOW}"
echo "╔════════════════════════════════════════════╗"
echo "║   KB Core — All Hooks Test Script           ║"
echo "║   Watch kbd_sensor output in Terminal 1     ║"
echo "╚════════════════════════════════════════════╝"
echo -e "${NC}"
echo "Starting in 3 seconds..."
sleep 3

# ─────────────────────────────────────────────
section "TEST 1 — process_exec / process_exit"
# ─────────────────────────────────────────────
echo "Expect: [process_exec] and [process_exit] events"
ls /tmp > /dev/null
pause
echo "true" > /dev/null
ok "process_exec / process_exit (via ls, true)"
pause

# ─────────────────────────────────────────────
section "TEST 2 — privilege_change"
# ─────────────────────────────────────────────
echo "Expect: [privilege_change] event, possibly 🔴 ESCALATION"
echo "(Requires sudo — will prompt for password)"
sudo -v   # refresh/validate sudo credential, triggers commit_creds
sudo whoami > /dev/null
ok "privilege_change (via sudo whoami)"
pause

# ─────────────────────────────────────────────
section "TEST 3 — file_access (sensitive paths)"
# ─────────────────────────────────────────────
echo "Expect: [file_access] 🔴 SENSITIVE for each path"

cat /etc/shadow > /dev/null 2>&1
ok "file_access — /etc/shadow"
pause

cat /etc/passwd > /dev/null 2>&1
ok "file_access — /etc/passwd"
pause

sudo cat /etc/sudoers > /dev/null 2>&1
ok "file_access — /etc/sudoers"
pause

ls /root/ > /dev/null 2>&1
ok "file_access — /root/"
pause

# ─────────────────────────────────────────────
section "TEST 4 — network_connect (outbound)"
# ─────────────────────────────────────────────
echo "Expect: [network_connect] -> <ip>:<port>"
curl -s -m 3 http://example.com > /dev/null 2>&1
ok "network_connect (via curl to example.com:80)"
pause

curl -s -m 3 https://1.1.1.1 > /dev/null 2>&1
ok "network_connect (via curl to 1.1.1.1:443)"
pause

# ─────────────────────────────────────────────
section "TEST 5 — network_bind (listening)"
# ─────────────────────────────────────────────
echo "Expect: [network_bind] listen <ip>:<port>"
python3 - <<'EOF' &
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999))
s.listen(1)
time.sleep(1)
s.close()
EOF
BIND_PID=$!
ok "network_bind (python socket on 0.0.0.0:9999)"
wait "$BIND_PID" 2>/dev/null
pause

# ─────────────────────────────────────────────
section "TEST 6 — memory_mmap (RWX / anon+exec)"
# ─────────────────────────────────────────────
echo "Expect: [memory_mmap] 🔴 RWX! ANON"
python3 - <<'EOF'
import mmap
m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
m.close()
EOF
ok "memory_mmap (RWX anonymous mapping)"
pause

# ─────────────────────────────────────────────
section "TEST 7 — memory_mprotect (W^X violation pattern)"
# ─────────────────────────────────────────────
echo "Expect: [memory_mprotect] event with PROT containing X"
python3 - <<'EOF'
import ctypes, mmap, os

libc = ctypes.CDLL("libc.so.6", use_errno=True)

PAGESIZE = mmap.PAGESIZE
PROT_READ  = 0x1
PROT_WRITE = 0x2
PROT_EXEC  = 0x4

# Allocate a writable anonymous page first
m = mmap.mmap(-1, PAGESIZE, prot=PROT_READ | PROT_WRITE)

# Get the address of the mapping
addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
# Align down to page boundary (mmap.mmap already page-aligns, but be safe)
page_addr = addr - (addr % PAGESIZE)

# Call mprotect() directly via libc — this is what fires
# the kprobe:mprotect / sys_enter_mprotect hook
ret = libc.mprotect(
    ctypes.c_void_p(page_addr),
    ctypes.c_size_t(PAGESIZE),
    ctypes.c_int(PROT_READ | PROT_EXEC)
)

if ret != 0:
    err = ctypes.get_errno()
    print(f"mprotect failed: errno={err} ({os.strerror(err)})")
else:
    print("mprotect(PROT_READ|PROT_EXEC) succeeded — W^X transition triggered")

m.close()
EOF
ok "memory_mprotect (write→exec transition via ctypes libc call)"
pause

# ─────────────────────────────────────────────
section "TEST 8 — Composite Attack Simulation"
# ─────────────────────────────────────────────
echo "Simulates a realistic chain: exec -> network -> privilege"
echo "Expect: multiple correlated events from one lineage"

bash -c '
    echo "  [chain] spawned bash"
    curl -s -m 3 http://example.com > /dev/null 2>&1
    echo "  [chain] outbound connection made"
    cat /etc/passwd > /dev/null 2>&1
    echo "  [chain] sensitive file touched"
'
ok "composite chain (bash -> curl -> cat /etc/passwd)"
pause

# ─────────────────────────────────────────────
section "TEST COMPLETE"
# ─────────────────────────────────────────────
echo -e "${GREEN}"
echo "All 9 event types have been triggered:"
echo "  1. process_exec"
echo "  2. process_exit"
echo "  3. privilege_change"
echo "  4. file_access"
echo "  5. network_connect"
echo "  6. network_bind"
echo "  7. memory_mmap"
echo "  8. memory_mprotect"
echo "  9. (composite chain — multiple types correlated)"
echo -e "${NC}"
echo "Check Terminal 1 (kbd_sensor) output to confirm all fired."
echo ""