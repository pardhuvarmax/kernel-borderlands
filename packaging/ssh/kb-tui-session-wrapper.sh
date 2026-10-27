#!/bin/sh
# /usr/local/bin/kb-tui-session-wrapper.sh
# ForceCommand target for sshd@kb-operator — reports session start/end into
# kbd's audit log, then runs the unified kbopd binary.
set -u

/usr/local/bin/kbctl ssh session-start --remote-addr "${SSH_CONNECTION:-unknown}"

# FIX: Point directly to the unified binary path managed by your Makefile
/usr/local/bin/kbopd
status=$?

/usr/local/bin/kbctl ssh session-end --remote-addr "${SSH_CONNECTION:-unknown}"

exit "$status"

