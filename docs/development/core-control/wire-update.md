**Status:** Completed — `StartTimeNs` is in `wireZoneTransition` (`wire.go`), version check is at 3, and the reuse guard is enforced in `ControlPlane.OnZoneTransition` via `store.VerifyStartTime` before containment.

This is a wire-format change on my side, so your Go structs are now out of sync again. Concretely, you need to:

**1. Update `ZoneTransition` struct in `wire.go`** — add the new field in the right spot:

```go
type wireZoneTransition struct {
    Hdr           wireHeader
    Pid           uint32
    StartTimeNs   uint64  // NEW
    FromZone      uint32
    ToZone        uint32
    Score         float64
    TsNs          uint64
}
```

Field order and types must match the C struct exactly since it's a raw `#pragma pack(1)` memory layout, not a self-describing format — struct tags/binary.Read offsets need to line up byte-for-byte.

**2. Bump your version check to 3** — if you added the assert-on-mismatch logic I suggested, update the expected version constant. If you haven't added that yet, this is a good forcing function to do it now rather than later.

**3. Actually use `StartTimeNs` before calling `applyContainment(pid)`** — this is the part that matters functionally, not just decoding. You need to compare the incoming `StartTimeNs` against whatever you have on record for that PID (presumably from the last `ProcessState` you saw, or a lookup) and skip/no-op containment if they don't match. Just decoding the field without checking it doesn't actually close the reuse gap you flagged.

**4. Confirm `ProcessState` is 128 bytes on your end too**, if you haven't already updated for the `syscall_entropy_lifetime` field from the last round — this message didn't touch `ProcessState` again, so if you already fixed that, no further change is needed there.

Worth explicitly mentioning: `ProcessState` didn't change this round, only `ZoneTransition` did — so you don't need to re-derive the 128-byte layout, just add the one new field to the transition struct and wire up the actual reuse check.
