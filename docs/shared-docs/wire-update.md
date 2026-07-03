this is a wire-format change on my side, so your Go structs are now out of sync again. Concretely,  you need to:

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

**2. Bump her version check to 3** — if she added the assert-on-mismatch logic we suggested, update the expected version constant. If she hasn't added that yet, this is a good forcing function to do it now rather than later.

**3. Actually use `StartTimeNs` before calling `applyContainment(pid)`** — this is the part that matters functionally, not just decoding. She needs to compare the incoming `StartTimeNs` against whatever she has on record for that pid (presumably from the last `ProcessState` she saw, or a lookup) and skip/no-op containment if they don't match. Just decoding the field without checking it doesn't actually close the reuse gap she flagged.

**4. Confirm `ProcessState` is 128 bytes on her end too**, if she hasn't already updated for the `syscall_entropy_lifetime` field from the last round — this message didn't touch `ProcessState` again, so if she already fixed that, no further change needed there.

Worth explicitly telling her: `ProcessState` didn't change this round, only `ZoneTransition` did — so she doesn't need to re-derive the 128-byte layout, just add the one new field to the transition struct and wire up the actual reuse check.