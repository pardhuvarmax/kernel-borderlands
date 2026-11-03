# Per-process counters message (design proposal)

**Status: PROPOSED. No code exists. Implementation needs explicit operator sign-off** (it adds a wire
message between `kb-core` and `kb-control-plane`, `docs/architecture/kbd-contracts.md`'s "C and Go sides
change together" rule, and it invalidates the existing attack-lab corpora for retraining).

Plan items covered: B4 (`bytes_sent`), the sensor-side half of B5 (sensitive-file count, credential-change
count, sequence evidence) and B6 (per-process drop counts so `telemetry_gap` is measured). Background:
`docs/development/control-aads/learned-policy-retraining.md` §3 and §3b.

## 1. Problem

`kbd` sees four things per process: `process_state` (msg_type 1, a fixed 128-byte struct with six
dimension scores), `zone_transition`, `process_exit` and `net_flow`. The evidence that would separate a
credential theft from `sudo tar /etc`, or an offsite backup from exfiltration, is held in the sensor's
userspace (`kb_evidence_t`: `cred_file_count`, the event-type sequence ring, counters) or not collected at
all (bytes sent, per-process drops). It never reaches `kbd`, so no learned policy or tree-level rule can
use it.

## 2. Proposal: one new message, not a bigger `process_state`

Do **not** grow msg_type 1. It is documented, tested and consumed as exactly 128 bytes (`wire-protocol.md`,
`parseProcessState`), and it has no spare field. Instead add **msg_type = 11, `process_counters`**
(sensor → `kbd`, over `kbd.sock`). `wire-protocol.md` lists 11+ as free. Precedent: msg_type 9 and 10 were
added the same way with `KB_WIRE_VERSION` left at 3 and the documented behaviour that an older `kbd`
ignores an unknown msg_type. A new `kbd` must likewise tolerate a sensor that never sends it.

Proposed layout (packed, little-endian; sizes are a draft to review, not a contract yet):

```
kb_wire_header hdr            4
uint32 pid                    4
uint64 start_time_ns          8   // PID-reuse guard, same as process_state
uint64 window_end_ns          8
uint32 sensitive_file_count   4   // cumulative, saturating
uint32 cred_change_count      4   // cumulative, saturating
uint32 bytes_sent_kib         4   // cumulative KiB written to network sockets, saturating
uint32 dropped_events         4   // ring-buffer/perf drops attributed to this pid in the window
uint32 seq_signature          4   // hash of the last N event types (see 4.3)
uint32 _reserved              4
```
Total: 48 bytes. Sent only when a counter changed since the last send for that pid, at most once per
second per pid (and flushed on exit), never per syscall.

## 3. Sensor side (kb-core)

| Counter | Source | Notes |
|---|---|---|
| `sensitive_file_count` | existing `KB_EVT_FILE_ACCESS` handling in `kbd_sensor.c` | userspace only; `cred_file_count` already exists in `kb_evidence_t` |
| `cred_change_count` | existing `commit_creds` handling | userspace only |
| `seq_signature` | existing sequence ring in `kb_evidence_t` | see 4.3 |
| `dropped_events` | per-pid accounting around the existing drop marker (`KB_EVT_DROPPED_TELEMETRY`) | the marker exists; the per-pid attribution does not (B6) |
| `bytes_sent_kib` | **new eBPF hook** on `write`/`sendto`/`sendmsg` for socket fds | the only new kernel-side instrumentation; see 5 |

The first three are bookkeeping on data the sensor already has. They carry little kernel risk and could
ship on their own if the operator wants the bump split.

## 4. `kbd` side

1. `parseProcessCounters` with a strict length check (the `parseNetFlow` 22-vs-24 bug is the reason; add the
   short-frame tests the same way) and a `MessageHandler.OnProcessCounters`.
2. A per-pid cache, evicted on exit (same pattern as `netFlowCache`), joined into `OnProcessState`.
3. `seq_signature` is only useful if it is decoded into something a model can use. Decide before
   implementing: a small fixed set of named patterns (for example "credential read then connect",
   "exec then connect") exported as 0/1 features, not a raw hash, which a model cannot generalise from.
4. New schema v5 keys: `sensitive_file_count`, `cred_change_count`, `bytes_sent_kib` (log-scaled in the
   feature, since the threat model is low-and-slow), `dropped_events`, and `telemetry_gap` computed from
   `dropped_events` instead of inferred from missing dimensions. `kb-aads/features/schema.py` and its tests
   change in the same commit; `SCHEMA_VERSION` bumps and v4 checkpoints are refused by `gate_checkpoint`.

## 5. Risk and rollout

- **`bytes_sent` is the dangerous part.** A syscall-level hook runs on every `write`. It must filter to
  socket fds in-kernel, aggregate in a per-pid BPF map, and be read and batched by userspace; a per-event
  ring-buffer submit would repeat the telemetry flood that caused real outages (see CHANGELOG 1.1.0). It
  needs an opt-out environment variable in the style of `KB_TLS_GO_UPROBE=0`, off-by-default until tested,
  and a load test on an isolated VM with the installed sensor stopped and restored (the Go-TLS-uprobe bug
  and the `kb_cred_snapshot` padding bug both stopped a sensor or froze a VM). Measure overhead against
  the C3 benchmark before and after.
- **Corpora.** Every existing corpus lacks these fields. Fields a corpus predates take the schema's
  missing-value default (as `baselines.py` now does), so old runs stay loadable but are not comparable. A
  fresh capture (Workstream D, `KB_OBSERVE_ONLY`, operator approval) and a retrain (Workstream A) follow.
- **Compatibility.** Additive: no existing struct changes, `KB_WIRE_VERSION` stays 3 unless the operator
  prefers a bump to make the change visible.
- **Tests required on both sides:** C struct size assertion, Go round-trip and short-frame rejection,
  `kbd` ignoring an absent message, schema tests, and a live check that the counters match a known
  workload (for example `dd` to a socket of known size).

## 6. Namespaces, to avoid a repeated mix-up

The sensor's BPF event enum (`KB_EVT_*`: 9 is TLS, 10 is the dropped-telemetry marker) and the wire
`msg_type` values (9 is net flow, 10 is containment ack) are separate numbering spaces. A new `PTRACE_USED`
event would take the next `KB_EVT_*` value (11) and does not collide with wire msg_type 11.

## 7. Decisions needed from the operator

1. Approve adding msg_type 11 (this document), or choose a different shape.
2. One combined change, or split: the userspace-only counters first, `bytes_sent` after its own review.
3. Whether `KB_WIRE_VERSION` should bump for visibility.
4. Which `seq_signature` patterns to export (4.3).
