# Core to Control Plane Development Discussions

This directory contains specifications and architectural notes for Go Control Plane (`kbd`) development tasks.

## 📂 Catalog

0. **[Control Plane Work Catalog](control-plane-catalog.md)**: Full inventory of what's built in `kb-control-plane` and what's still outstanding, including gaps not written up elsewhere. Start here for "what's done / what's left."
1. **[UDS gRPC Binding Spec](kba_uds_binding_spec.md)**: Details the migration of the gRPC listener from TCP port `:50051` to Unix Domain Socket `/run/kb/kba.sock` with permission appraisal.
2. **[IPC v3 Wiring Specifications](ipc-v3-wiring.md)**: Specifications for IPC wire protocol transitions.
3. **[June 26 Status Report](june26-26.md)**: Historical development updates.
