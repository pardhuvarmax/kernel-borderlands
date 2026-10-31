# src

The operator console's Rust source (`kbopd` / `kb-tui`).

| File | Role |
| --- | --- |
| `main.rs` | Entry point; locates the sibling `mcp-server` binary |
| `grpc.rs` | Connects to `kbd` over `/run/kb/kba.sock` and spawns the streaming/polling tasks |
| `app.rs` | Application state and the messages background tasks send to the main loop |
| `ui.rs` | Rendering |
| `query.rs` | The typed query-console commands |
| `dash.rs` | Serves the embedded web dashboard and routes dashboard actions into the TUI pipeline |
| `demo.rs` | Synthetic data used when `kbd` is unreachable (the UI then shows `[OFFLINE]` / `[DEMO DATA]`) |
| `kb.rs` | Shared types |

Build and usage: [`../README.md`](../README.md).
