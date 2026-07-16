#!/bin/bash
# kb-core/scratchpad/inspect-bpf-state.sh
#
# Dumps the live state of kbd_sensor's LSM programs and containment/
# sensitive-path maps, for manually confirming enforcement is actually
# happening (not just "loaded") after a rebuild. Requires root — run with
# sudo. kbd_sensor must already be running (see run-sensor.sh).
#
# Used during this session to catch two real bugs that "program loaded &
# attached" alone did not reveal:
#   - kb_sensitive_paths had the right key but bpf_d_path()'s buffer
#     wasn't zero-padded, so lookups silently missed (fixed in
#     kb_lsm_file_open, kb-core/ebpf/kbd_sensor.bpf.c).
#   - contained_pids_map stayed empty even after kbd logged
#     SET_CONTAINMENT_* in its audit trail, because the wire msg_type for
#     containment commands didn't match between Go and C (fixed in
#     kb-control-plane/internal/ipc/types.go).
set -euo pipefail

echo "=== bpftool prog list (lsm) ==="
bpftool prog list | grep -B1 -A1 "lsm" || echo "(none found — is kbd_sensor running?)"

echo
echo "=== kb_sensitive_paths map ==="
SENSITIVE_MAP_ID=$(bpftool map show | grep -i "sensit" | head -1 | cut -d: -f1)
if [ -n "${SENSITIVE_MAP_ID:-}" ]; then
  echo "map id: $SENSITIVE_MAP_ID"
  bpftool map dump id "$SENSITIVE_MAP_ID"
else
  echo "(not found — is kbd_sensor running?)"
fi

echo
echo "=== contained_pids_map ==="
CONTAINMENT_MAP_ID=$(bpftool map show | grep -i "contained_pids" | head -1 | cut -d: -f1)
if [ -n "${CONTAINMENT_MAP_ID:-}" ]; then
  echo "map id: $CONTAINMENT_MAP_ID"
  bpftool map dump id "$CONTAINMENT_MAP_ID"
else
  echo "(not found — is kbd_sensor running?)"
fi
