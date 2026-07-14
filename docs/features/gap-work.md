# Gap Work Improvements

**Document Version:** 2.0
**Component:** Userspace Sensor / eBPF Containment Engine
**Status:** COMPLETED (Signed off by PardhuVarma on 2026-07-14)

![Completed Stamp](/home/emergence/.gemini/antigravity-cli/brain/3e50ec6a-0832-4371-b0c0-153dd47fa7da/completed_badge_1784023276772.jpg)

---

# Overview

This document describes two small implementation improvements identified during code review of the containment restore path, plus the runtime validation step needed to confirm they actually close the loop. Neither issue is a blocker for the current release — both were flagged as "worth a second look" rather than "must fix now" — but both are cheap to address while the restore function is already being touched, and both materially help future debugging.

The improvements are:

1. Checking the return value of `bpf_map_delete_elem()`
2. Bounding the format specifier used to log `cmd->reason`

A third section documents the runtime validation procedure that confirms these (and the restore path generally) actually behave as intended — since code review alone does not close the loop on whether the kernel map is really being cleaned up.

These changes do not modify the containment model, policy, or LSM enforcement logic. They strengthen correctness and observability in the existing implementation.

---

# Background

The containment engine maintains the runtime state of isolated processes inside the kernel using the `contained_pids_map` eBPF hash map.

When a process is isolated:

```
PID
↓
contained_pids_map
↓
Containment Level
```

When the process is restored, its entry should be completely removed from the map — not just have its level reset to zero.

During review, two small implementation gaps were flagged in the restore path:

* `bpf_map_delete_elem()` failures other than "key already gone" are currently silent
* the fixed-length `reason` field can be logged unsafely if it isn't null-terminated

Neither is urgent, but both are worth fixing now since the function is already being touched for this work, and both become important the first time someone needs to debug a "restore didn't actually work" report from the dashboard.

---

# Improvement 1 — Check the `bpf_map_delete_elem()` Return Value

## Current Behavior

The restore implementation removes the process from the BPF map using:

```c
bpf_map_delete_elem(map_fd, &pid);
```

The return value is ignored. If deletion succeeds, everything works correctly. If it fails, the application currently proceeds as though restoration completed successfully — the dashboard can end up reporting "Restored" while the kernel still holds the entry.

## Why This Matters

This isn't urgent today, but if it ever fails for a reason other than "key already gone" — for example `EINVAL` from a map-level issue — that failure is currently silent. Other possible causes include an invalid map file descriptor, a map that's no longer pinned, or insufficient permissions. None of these are things you want to discover only when someone reports that a restore "didn't actually work."

## Recommended Fix

```c
if (bpf_map_delete_elem(map_fd, &pid) != 0 && errno != ENOENT) {
    fprintf(stderr, "[SENSOR] delete_elem failed for PID %u: %s\n", pid, strerror(errno));
}
```

## Why `ENOENT` Is Excluded

`ENOENT` just means the key is already gone. From a restore perspective that's the desired end state, so it isn't an error worth logging — only genuine deletion failures are.

## Benefit

This gives deterministic, loggable evidence the next time a "restore didn't actually work" report comes in from the dashboard, without changing any runtime behavior.

---

# Improvement 2 — Bound the Format Specifier for `cmd->reason`

## Current Structure

```c
char reason[64];
```

On the Go side, the reason string is copied into this array with:

```go
copy(reasonBytes[:], []byte(reason))
```

## The Problem

This is a **pre-existing risk from the original struct design**, not something newly introduced — but it's worth fixing while this function is already being touched.

If `reason` is 64 bytes or longer, Go's `copy()` fills the destination array completely and does **not** null-pad it. There's no guarantee of a terminating null byte. The array can end up as:

```
[A][A][A][A]...[A]
```

instead of the assumed:

```
[A][A][A]...[A][\0]
```

The current logging call:

```c
printf("...%s...", cmd->reason);
```

uses `%s`, which expects a null-terminated string. If no terminator is present, `printf()` keeps reading past the end of the struct until it happens to hit a zero byte elsewhere in memory — garbage characters, leaked adjacent memory, and formally undefined behavior, even if a crash is unlikely in practice.

## Recommended Fix

```c
printf(
    "[SENSOR] Restored PID %u, reason=\"%.64s\"\n",
    pid,
    cmd->reason
);
```

The `%.64s` precision specifier caps the number of bytes read at 64, so `printf()` never reads past the field regardless of whether a null terminator is present. No protocol or struct-layout change is required.

## Benefit

Removes the undefined-behavior read, keeps the wire format fully compatible, and makes log output deterministic.

---

# What Confirms This Is Actually Done

Code review alone doesn't close the loop here — the real path needs to be run:

```bash
./kbctl process isolate --pid 9999 --reason "test"
# confirm PID 9999 shows contained

./kbctl process restore --pid 9999   # or whatever the level-0 command is

# confirm the BPF map entry is gone, not just zeroed:
bpftool map lookup pinned /sys/fs/bpf/contained_pids_map key 9999 0 0 0
```

## Expected Result

```
key not found
```

## What It Would Look Like If Wrong

```
value:
00 00 00 00
```

That would mean the implementation only reset the containment level to zero rather than deleting the entry. Both currently behave similarly from the LSM's perspective, but they are **not semantically equivalent** — deleting the key keeps the map clean, avoids stale entries, and avoids ambiguity for future features that may key off entry existence rather than level.

The `bpftool map lookup` step is the one that actually distinguishes "deleted" from "zeroed" — it's worth having Pardhu run it once, live, before Task 1 is called closed.

---

# Overall Impact

| Improvement | Benefit |
|---|---|
| Check `bpf_map_delete_elem()` return value | Surfaces restoration failures instead of leaving them silent |
| Bound `cmd->reason` logging with `%.64s` | Removes undefined behavior from a non-null-terminated field |
| Runtime validation via `bpftool` | Confirms the entry is actually deleted, not merely zeroed |

None of these changes touch containment policy or LSM enforcement logic. They improve correctness and observability in the restore path with minimal, low-risk edits.

---

# Acceptance Criteria

This work is considered complete when:

* `bpf_map_delete_elem()` return values are checked, and failures other than `ENOENT` are logged with a descriptive message.
* `cmd->reason` is logged using the bounded `%.64s` format specifier rather than unbounded `%s`.
* `./kbctl process isolate --pid 9999 --reason "test"` followed by the restore command results in `bpftool map lookup pinned /sys/fs/bpf/contained_pids_map key 9999 0 0 0` reporting **"key not found"**, not a zeroed value.
* Pardhu (or another reviewer) has run the `bpftool` validation step live at least once before Task 1 is marked closed.
* Dashboard-reported restore state remains consistent with actual kernel map state.