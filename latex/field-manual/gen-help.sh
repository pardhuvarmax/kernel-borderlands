#!/bin/sh
# Regenerates generated/*.txt (real --help output of every kbctl command and
# the daemons) so the manual's CLI reference cannot drift from the binaries.
# Usage: ./gen-help.sh /path/to/bin   (default ../../bin)
set -eu
BIN="${1:-$(dirname "$0")/../../bin}"
OUT="$(dirname "$0")/generated"
mkdir -p "$OUT"
h() { name="$1"; shift; "$BIN/kbctl" "$@" --help > "$OUT/kbctl-$name.txt" 2>&1 || true; }
h root
for c in policy workload zone process audit stats ssh dashboard tui up down status; do h "$c" "$c"; done
h policy-reload policy reload
h workload-keygen workload keygen
h workload-sign workload sign
h workload-reload workload reload
h zone-override zone override
h process-isolate process isolate
h audit-export audit export
h audit-verify audit verify
h ssh-up ssh up
h ssh-down ssh down
h ssh-status ssh status
h ssh-connect ssh connect
h ssh-add-key ssh add-key
h dashboard-up dashboard up
h dashboard-open dashboard open
h dashboard-status dashboard status
"$BIN/kbd" --help > "$OUT/kbd.txt" 2>&1 || true
"$BIN/kb-checker" monitor --help > "$OUT/kb-checker-monitor.txt" 2>&1 || true
"$BIN/kb-checker" check --help > "$OUT/kb-checker-check.txt" 2>&1 || true
echo "generated $(ls "$OUT" | wc -l) files in $OUT"
