#!/bin/bash
# kb-core/scratchpad/run-sensor.sh
#
# (Re)starts kbd_sensor in the background, logging to a local runtime dir.
# Requires root (loads eBPF/LSM hooks) — run with sudo.
#
# Adapted from an interactive live-verification session used to confirm:
#   - the sensitive_paths config pipeline (policy.yaml -> kbd -> wire -> sensor)
#   - the containment-triggered LSM file-block fix
# See docs/development/core-control/in-context-mitigation.md for the bugs
# this session found and fixed (connect-time hang, frame-stash collision,
# zero-padding mismatch, containment msg_type mismatch, blanket-vs-gated
# blocking).
set -euo pipefail

RUNTIME_DIR="${KB_SCRATCH_DIR:-/tmp/kb-dev}"
LOG="$RUNTIME_DIR/kbd_sensor.log"
PIDFILE="$RUNTIME_DIR/kbd_sensor.pid"

mkdir -p "$RUNTIME_DIR"

if [ -f "$PIDFILE" ]; then
  OLDPID=$(cat "$PIDFILE")
  if kill -0 "$OLDPID" 2>/dev/null; then
    echo "stopping old sensor pid=$OLDPID"
    kill -INT "$OLDPID"
    sleep 1
  fi
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."
: > "$LOG"
nohup ./build/kbd_sensor >> "$LOG" 2>&1 &
SENSOR_PID=$!
disown
echo "$SENSOR_PID" > "$PIDFILE"
chmod 644 "$LOG" "$PIDFILE"
echo "started kbd_sensor pid=$SENSOR_PID (log: $LOG)"

sleep 3
if ! kill -0 "$SENSOR_PID" 2>/dev/null; then
  echo "ERROR: kbd_sensor exited immediately, see $LOG" >&2
  tail -60 "$LOG" >&2
  exit 1
fi

echo "still running, log tail:"
tail -20 "$LOG"
