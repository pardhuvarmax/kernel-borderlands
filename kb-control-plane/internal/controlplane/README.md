# Control Plane Core

Main control plane logic:
- Event aggregation from eBPF layer
- Process state management (zone, score, history)
- gRPC API gateway (including GetSystemStats RPC for MCP)
- Policy evaluation
- Operator interface (SSH service management and TUI spawning)
