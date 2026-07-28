# KB Event Contract — kb-core ↔ kb-control-plane

**Corrected — this doc previously described a contract that was never actually
implemented.** Checked against actual source: none of the 9 `event_type` values
below, nor their per-type metadata keys, appear anywhere in
`kb-control-plane/internal/controlplane/controlplane.go`. The doc's own closing
"Open question for Tejaswini" (routing by `event_type` vs. a pre-computed
`score_delta`) suggests this was written before implementation settled the
question — and it settled differently than sketched here. What's below now
reflects what's actually on the wire, verified by grep against every
`fanOutEvent(&pb.KBEvent{...})` call site (there are exactly two).

## What kb-core ↔ kb-control-plane actually looks like

This is really two separate contracts, not one:

1. **C → Go, `kbd.sock`, hand-packed structs** (not what this doc's old
   `event_type` list was describing): `kb_wire_process_state`,
   `kb_wire_zone_transition`, `kb_wire_process_exit` — see
   `kb-core/userspace/bridge/kb_bridge.h` and
   `docs/development/core-control/wire-protocol.md` (also flagged stale in
   places — check both). None of these structs have an `event_type` field.
   Separately, `kb_unified_event.event_type` (`kbd_sensor.bpf.c`) is a
   kb-core-*internal* enum (`KB_EVT_PROCESS_EXEC`=0 through
   `KB_EVT_DROPPED_TELEMETRY`=10) used for the sensor's own ring-buffer
   dispatch and console output — it never crosses the wire to Go as a named
   field either.

2. **Go → gRPC clients, `kba.sock`, `pb.KBEvent.EventType` (string)** — this
   is the actual "`event_type`" that exists on any wire in this system, and
   it has exactly two live values, confirmed via every `fanOutEvent` call
   site in `controlplane.go`:

   - `"process_state"` — emitted by `OnProcessState` on every incoming
     `kb_wire_process_state` message. `Metadata` keys actually populated:
     `zone`, `composite`, `dim_syscall`, `dim_privilege`, `uid`.
   - `"zone_transition"` — emitted by `OnZoneTransition` on every zone
     change. `Metadata` keys actually populated: `from_zone`, `to_zone`.

   Both carry `Pid`, `Ppid` (state only), `Comm`, `ScoreDelta`, `Timestamp`
   as top-level `KBEvent` fields (see `proto/kb.proto`'s `KBEvent` message)
   — there is no per-`event_type` metadata schema beyond the two lists
   above; nothing routes on `syscall_nr`, `filename`, `dst_ip`,
   `addr`/`length`/`prot`, etc. the way the old version of this doc implied.

3. **Alerts are a separate stream entirely** — `pb.Alert` (not `KBEvent`),
   emitted via `fanOutAlert`, currently only for `BORDERLANDS` zone entry
   (`alert_type: "BORDERLANDS_ENTRY"`). Not part of the `event_type`
   discussion above at all.

## The open question this doc used to end on

*"Does scoring engine route by event_type to apply weights, or does kb-core
need to send pre-computed score_delta?"* — resolved, in code: kb-core sends a
pre-computed `EMAScore`/`ScoreDelta` (via `kb_wire_process_state`), and Go
just forwards it in `KBEvent.ScoreDelta`. Nothing on the Go side branches on
`event_type` to compute or reweight a score — scoring is entirely kb-core's
job (`kb_scoring.c`), consistent with `internal/policy/policy.go`'s comment
that "zone classification moved fully to kb-core... arrives pre-computed."

## Known related staleness (not fixed here, flagging while in this area)

`docs/development/control-aads/kb-events-swarm-ingestion-gap.md` documents
that nothing in `kb-aads` currently consumes either `event_type` — this
contract is correctly implemented and live on the `kb-control-plane` side,
but has no consumer yet on the AADS side.
