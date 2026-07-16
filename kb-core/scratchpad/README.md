# kb-core/scratchpad

Manual, root-requiring verification scripts used during interactive debugging sessions — not part of the automated test suite (`kb-core/tests/`), not run in CI. Kept here as reusable session notes rather than one-off temp files.

- `run-sensor.sh` — (re)start `kbd_sensor` in the background, logging to `$KB_SCRATCH_DIR` (default `/tmp/kb-dev`).
- `inspect-bpf-state.sh` — dump the live LSM program list and `kb_sensitive_paths`/`contained_pids_map` state via `bpftool`, to confirm enforcement is actually active rather than just "loaded."

Both require `sudo`. `kbd` (the control plane) must already be running and `kbd_sensor` must be built (`make` from `kb-core/`) before using these.

These exist because two real bugs in this codebase were only caught by checking live kernel/map state, not by build success or "prog loaded" alone — see `docs/development/core-control/in-context-mitigation.md` for what they were and how they were found.
