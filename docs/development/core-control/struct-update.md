**Struct update — before you finalize `wire.go`:**

`kb_wire_process_state` grew by one field since you last read it: added `double syscall_entropy_lifetime`, sitting between `ema_score` and `zone`. New size is **128 bytes** (not 120, not the spec's 122).

```c
struct kb_wire_process_state {
    struct kb_wire_header hdr;              // magic(2) + version(1) + msg_type(1) = 4
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char     comm[16];
    uint64_t start_time_ns;
    uint64_t last_updated_ns;
    double   dim_score[6];                  // KB_DIM_COUNT, index 1 = KB_DIM_SYSCALL
    double   composite_score;
    double   ema_score;
    double   syscall_entropy_lifetime;       // ← NEW — advisory only, see below
    uint32_t zone;
    uint32_t event_count;
};                                            // 128 bytes total, #pragma pack(1)
```

**What it means:** advisory-only, full-lifetime syscall-distribution entropy for the pid. It does **not** feed `composite_score`/`ema_score`/zone — that's `dim_score[KB_DIM_SYSCALL]` (index 1), which is now a windowed/EMA-smoothed value, not lifetime. Up to you whether it gets its own SQLite column or just rides along in the audit row — it's history, not the live risk signal.

**`KB_WIRE_VERSION` bumped to 2** for this change. Worth having your decoder branch on `version` rather than trying to infer field count from `length` — this format's moved twice already and probably isn't done moving.

**Also, going forward:** since you're decoding by length prefix already, add an assert that `length` matches the expected size for a given `msg_type`+`version` and log loudly on mismatch, instead of trusting either side. That would've caught this automatically instead of you having to catch it by re-measuring.

`KB_DIM_SYSCALL` population — the thing you flagged — is fixed as of this build, so `dim_score[1]` should be nonzero once you're seeing real traffic.


Date/Time : July 03rd 2026, Friday 11:58am IST.