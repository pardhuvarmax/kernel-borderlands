# checkerclient

`checkerclient.go`: dials `kb-checker`'s diagnostic socket (`/run/kb/kbc.sock`) and asks whether it considers itself healthy, so `kbd` can report that status without duplicating the checker's own heartbeat and signature audits. `kb-checker` is currently kept down by operator decision (see the root changelog).
