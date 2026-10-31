# logx

`logx.go`: a keyed log rate-limiter ("+N similar suppressed") used for per-event log lines so a telemetry flood cannot flood the journal. Security-relevant lines (containment refusals, tamper evidence, audit chain breaks) deliberately do not use it. Tests: `logx_test.go`.
