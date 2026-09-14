#!/bin/sh
# /usr/local/bin/kb-tui-session-wrapper.sh
# ForceCommand target for sshd@kb-operator — reports session start/end into
# kbd's audit log (see control-plane-catalog.md §2.12 step 5), then runs
# kb-tui. Audit logging is best-effort: kbctl's own session-start/session-end
# subcommands never fail this script's exit status, so an audit-log outage
# never blocks legitimate operator access (see kbctl ssh session-start's own
# comment for the reasoning) — this script inherits that same principle by
# not checking their exit codes.
set -u

/usr/local/bin/kbctl ssh session-start --remote-addr "${SSH_CONNECTION:-unknown}"

/usr/local/bin/kb-tui
status=$?

/usr/local/bin/kbctl ssh session-end --remote-addr "${SSH_CONNECTION:-unknown}"

exit "$status"
