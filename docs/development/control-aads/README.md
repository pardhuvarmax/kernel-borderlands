# Control Plane to AADS Development Discussions

## Document Catalog

- [`aads-development-plan.md`](aads-development-plan.md) — Design architecture and step-by-step implementation plan for Karthik to build out AADS (Ray, MARL, gRPC-over-UDS) inside `kb-aads`.
- [`ray-integration-walkthrough.md`](ray-integration-walkthrough.md) — Technical walkthrough for migrating local Python MARL agents to Ray Actors: actor lifecycle, distributed message passing, the Ray Swarm Orchestrator, and JJE (Judge/Jury/Executor) Ray integration.
- [`ray-shared-mutable-state.md`](ray-shared-mutable-state.md) — Proposal (needs Karthik's review): Ray's Plasma object store is immutable, so it can't hold shared *mutable* swarm state (e.g. mid-round vote tallies, persistent threat history). Proposes a dedicated `SwarmMemory` actor for round-scoped state and routing durable state through `kb-control-plane`'s existing storage instead of adding an external store — rejects Redis outright given the repo's no-TCP-surface constraint.
- [`aads-intelligence-roadmap.md`](aads-intelligence-roadmap.md) — Roadmap (needs Karthik's review) from the current skeleton Ray actors to trained agents: the RL/LLM hybrid split per agent role (Jury/Healer/Containment → RL, Hunter → QLoRA LLM, everything else → no model), JJE's "courthouse" oversight authority over sub-agents (severity-graded restart/revoke/termination response, quorum vs. unilateral action), and the data-pipeline/training/inference/validation/feedback-loop phases required to get there.
- [`dev-exfiltration-detection.md`](dev-exfiltration-detection.md) — Architectural guidance and algorithm designs for detecting slow data exfiltration via authorized sockets, using `kb-core`'s telemetry streams.
- [`real-comms-uds-verification.md`](real-comms-uds-verification.md) — How to run a real connection integration test between the Python AADS client and the live `kbd` daemon over `/run/kb/kba.sock`.
- [`walkthrough.md`](walkthrough.md) — AADS gRPC-over-UDS client implementation and mock verification tests.
