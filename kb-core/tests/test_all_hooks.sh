#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# KB Core — Hook Verification Test Script
# Triggers all 9 event types one at a time with labels,
# so output can be matched against kbd_sensor's live stream.
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

run_sudo_optional() {
    local cmd="$1"
    local desc="$2"
    echo -e "${YELLOW}  [Sudo Option] This test can run with sudo: $desc${NC}"
    read -t 5 -p "  Do you want to authorize sudo? (y/N) [Timeout 5s -> No]: " -n 1 -r choice
    echo ""
    if [[ "${choice:-n}" =~ ^[Yy]$ ]]; then
        if sudo -v; then
            eval "sudo $cmd"
        else
            echo -e "${RED}  Sudo authorization failed or rejected, falling back to non-sudo...${NC}"
            eval "$cmd"
        fi
    else
        echo -e "${YELLOW}  Sudo skipped, running without privilege...${NC}"
        eval "$cmd"
    fi
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
run_sudo_optional "whoami > /dev/null" "whoami (triggers commit_creds privilege change)"
ok "privilege_change test complete"
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

run_sudo_optional "cat /etc/sudoers > /dev/null 2>&1" "cat /etc/sudoers (triggers sensitive file open)"
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
# Align down to page boundary
page_addr = addr - (addr % PAGESIZE)

# Call mprotect() directly via libc
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
section "TEST 8 — Privilege & Credential Chain (SAFE -> SUSPICIOUS)"
# ─────────────────────────────────────────────
echo "Simulates: privilege change combined with sensitive credential reads"
echo "Expect: SAFE -> OBSERVED -> SUSPICIOUS transitions in a single process"

python3 - <<'EOF'
import time
import os

print(f"  [Chain A] Running in PID {os.getpid()}")

# 1. Read /etc/shadow (triggers sensitive file access -> transitions to OBSERVED/SUSPICIOUS)
try:
    with open("/etc/shadow", "r") as f:
        _ = f.read(10)
    print("  [Chain A] Step 1: Read /etc/shadow done")
except Exception as e:
    print(f"  [Chain A] Step 1 failed (shadow read): {e}")

time.sleep(1.5)

# 2. Read /etc/sudoers (sensitive file access -> SUSPICIOUS state)
try:
    with open("/etc/sudoers", "r") as f:
        _ = f.read(10)
    print("  [Chain A] Step 2: Read /etc/sudoers done")
except Exception as e:
    print(f"  [Chain A] Step 2 failed (sudoers read): {e}")

time.sleep(1.5)
EOF
ok "privilege & credential chain complete"
pause

# ─────────────────────────────────────────────
section "TEST 9 — Memory Injection Chain (SUSPICIOUS -> BORDERLANDS -> COMPROMISED)"
# ─────────────────────────────────────────────
echo "Simulates: cred file read -> RWX non-zero mapping -> RWX zero mmap"
echo "Expect: SAFE -> SUSPICIOUS -> BORDERLANDS -> COMPROMISED transitions"

python3 - <<'EOF'
import mmap
import time
import os
import ctypes

libc = ctypes.CDLL("libc.so.6", use_errno=True)
PAGESIZE = mmap.PAGESIZE

print(f"  [Chain B] Running in PID {os.getpid()}")

# 1. Read sensitive file (shadow) -> transitions to SUSPICIOUS
try:
    with open("/etc/shadow", "r") as f:
        _ = f.read(10)
    print("  [Chain B] Step 1: Read /etc/shadow done")
except Exception as e:
    print(f"  [Chain B] Step 1 failed (shadow read): {e}")

time.sleep(2)

# 2. Allocate RWX memory at a non-zero address (mprotect with RWX) -> transitions to BORDERLANDS
try:
    m = mmap.mmap(-1, PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
    page_addr = addr - (addr % PAGESIZE)
    # mprotect to PROT_READ | PROT_WRITE | PROT_EXEC (7) at non-zero address
    ret = libc.mprotect(ctypes.c_void_p(page_addr), ctypes.c_size_t(PAGESIZE), ctypes.c_int(7))
    if ret == 0:
        print("  [Chain B] Step 2: Wrote RWX at non-zero address done")
    else:
        print(f"  [Chain B] Step 2 mprotect failed: {ctypes.get_errno()}")
    m.close()
except Exception as e:
    print(f"  [Chain B] Step 2 failed: {e}")

time.sleep(2)

# 3. Allocate RWX memory at address 0 (mmap with NULL and RWX) -> transitions to COMPROMISED
try:
    m = mmap.mmap(-1, PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    print("  [Chain B] Step 3: Wrote RWX at zero address done")
    m.close()
except Exception as e:
    print(f"  [Chain B] Step 3 failed: {e}")

time.sleep(2)
EOF
ok "memory injection chain complete"
pause

# ─────────────────────────────────────────────
section "TEST 10 — C2 Outbound Connection Chain (SUSPICIOUS -> BORDERLANDS)"
# ─────────────────────────────────────────────
echo "Simulates: cred file read -> outbound connect to suspected C2 port (4444)"
echo "Expect: SAFE -> SUSPICIOUS -> BORDERLANDS transitions"

# Start a local listener on 4444 in the background so the connect works
python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 4444)); s.listen(1); s.accept()' &
LISTENER_PID=$!
sleep 0.5

python3 - <<'EOF'
import time
import os
import socket

print(f"  [Chain C] Running in PID {os.getpid()}")

# 1. Read sensitive file (shadow) -> transitions to SUSPICIOUS
try:
    with open("/etc/shadow", "r") as f:
        _ = f.read(10)
    print("  [Chain C] Step 1: Read /etc/shadow done")
except Exception as e:
    print(f"  [Chain C] Step 1 failed (shadow read): {e}")

time.sleep(2)

# 2. Outbound connection to port 4444 -> transitions to BORDERLANDS
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 4444))
    print("  [Chain C] Step 2: Connected to C2 port 4444 done")
    s.close()
except Exception as e:
    print(f"  [Chain C] Step 2 failed (connect): {e}")

time.sleep(2)
EOF

wait "$LISTENER_PID" 2>/dev/null || true
ok "C2 connection chain complete"
pause

# ─────────────────────────────────────────────
section "TEST COMPLETE"
# ─────────────────────────────────────────────
echo -e "${GREEN}"
echo "All hook event types and sequential attack chains have been triggered:"
echo "  1. process_exec / process_exit"
echo "  2. privilege_change"
echo "  3. file_access (sensitive paths floor)"
echo "  4. network_connect (HTTP/HTTPS)"
echo "  5. network_bind (listen socket)"
echo "  6. memory_mmap (RWX anon)"
echo "  7. memory_mprotect (W^X violation)"
echo "  8. Chain A: Privilege + Credential (transitions to SUSPICIOUS)"
echo "  9. Chain B: Memory Injection (transitions to BORDERLANDS/COMPROMISED)"
echo "  10. Chain C: C2 Connection (transitions to BORDERLANDS)"
echo -e "${NC}"
echo "Check Terminal 1 (kbd_sensor) and Terminal 2 (kbd/TUI) to verify alerts."
echo ""