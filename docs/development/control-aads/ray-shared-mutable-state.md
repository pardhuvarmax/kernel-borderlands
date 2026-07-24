# Ray Shared Mutable State for the AADS Swarm

- **Document Version:** 1.0
- **Component:** `kb-aads` (Ray actor swarm), touches `kb-control-plane` (gRPC/SQLite) at the boundary
- **Status:** Proposal — needs review. Nothing here is implemented; this is a design gap flagged against the existing walkthrough, for **Karthik (AADS Swarm Lead)** to confirm, amend, or reject.
- **Related docs:** [`ray-integration-walkthrough.md`](../development/control-aads/ray-integration-walkthrough.md) (§5 Judge/Jury/Executor, §6 refactoring blueprint), [`ADR-1`](../development/adr/ADR-1.md) (L1 `sync.Map` / L2 SQLite WAL storage design), [`kbd-contracts.md`](../architecture/kbd-contracts.md)

---

## The gap

`ray-integration-walkthrough.md` §1 describes Ray's Plasma object store as delivering "sub-millisecond shared memory speed" for inter-agent data. That's accurate for what Plasma actually is — but Plasma objects are **immutable once written** (`ray.put()` / an actor call's return value produces a fixed `ObjectRef`; there is no `ray.update(ref, ...)`). This is a deliberate Ray invariant: it's what makes zero-copy cross-process reads safe without locking.

The walkthrough's actor code (§6A/§6B) keeps each agent's own mutable state (`self.state`, `self.message_queue`) local to that actor's process — which is correct and fine. But nothing in the current design addresses **state that needs to be shared *and* mutated by multiple actors concurrently** — e.g., for the JJE consensus flow in §5:

- A running vote tally that more than one `Jury` actor might need to read mid-round (not just report back to `Judge`).
- A threat-confidence/reputation score that should persist and inform future consensus rounds, not just the current one.

Plasma cannot hold this. If the JJE design ever implies actors reading/writing shared state like this, it needs an explicit mechanism — this doc proposes one.

---

## Option A — Dedicated "memory owner" actor

The idiomatic Ray pattern: one actor owns the mutable state, everyone else mutates it via remote method calls. Ray serializes calls to a given actor by default (one call processed at a time), so this gets you mutual exclusion for free — no manual locking.

```python
@ray.remote
class SwarmMemory:
    def __init__(self):
        self._vote_tally: dict[str, list] = {}
        self._threat_history: dict[str, float] = {}

    def cast_vote(self, event_id: str, jury_id: str, vote: bool):
        self._vote_tally.setdefault(event_id, []).append((jury_id, vote))
        return len(self._vote_tally[event_id])

    def get_votes(self, event_id: str):
        return self._vote_tally.get(event_id, [])

    def update_threat_score(self, target: str, score: float):
        self._threat_history[target] = score
```

`Judge` creates one `SwarmMemory.remote()` per swarm startup (or per active consensus round) and passes the `ActorHandle` to each `Jury` actor at construction, or through a small registry actor. Jury actors call `memory.cast_vote.remote(...)` instead of only returning votes to `Judge` — this is what would let Jury actors observe each other's votes mid-round, if the consensus design ever needs that.

- **Tradeoffs**: a single actor serializes all writes — fine for small, write-light state (vote tallies), a bottleneck if every agent hits it every tick. Also a single point of failure: if the actor dies, in-flight shared state is gone unless `max_restarts` is set *and* the actor checkpoints its state somewhere durable.

### Mitigating the SPOF/bottleneck risk (without leaving Ray or UDS)

The risk above is largely a function of scoping `SwarmMemory` too broadly (one long-lived actor for the whole swarm). Scoping it **per active consensus round**, as already proposed above, resolves most of it as a side effect:

- **Bottleneck**: write volume per round is bounded (N jury actors, one vote each) — not a sustained hot loop. Round-scoping means contention never accumulates across rounds; each round's actor only ever sees that round's own small traffic.
- **Blast radius**: if a round's `SwarmMemory` actor dies, only that in-flight round is lost, not the whole swarm's state — `Judge` just restarts the round.

Further hardening, still with no new dependency or network surface:

1. **`max_restarts` / `max_task_retries` on the actor** — Ray transparently restarts a crashed actor and retries in-flight calls; cheap to add, no design change.
2. **`Judge` as fallback reconstructor** — `Judge` already holds `vote_refs` and calls `ray.get()` on them directly (§5B of the walkthrough), so it can reconstruct a round's tally straight from the Jury actors if `SwarmMemory` is unreachable, rather than treating `SwarmMemory` as the sole source of truth.
3. **Sharding, only if load actually demands it** — if round-scoping alone proves insufficient at real load, shard `SwarmMemory` itself (e.g. `hash(event_id) % N` across N shard actors) rather than reaching for an external store. This adds moving parts, so it should be justified by Karthik's actual measured load, not adopted preemptively.

## Option B — External store (e.g. Redis) — rejected

Shared mutable state lives outside Ray entirely. Any actor on any node reads/writes without funneling through one actor's call queue — scales better under write contention, and survives actor restarts since state isn't in-process.

```python
import redis
r = redis.Redis(host="localhost", port=6380)
r.hincrby(f"votes:{event_id}", jury_id, 1)
```

**This option is disqualified by existing architecture, not just disfavored on latency grounds.** `kba_uds_binding_spec.md` and `kb-checker/README.md` are both explicit and unconditional: *"There is no TCP fallback — UDS is the only transport, everywhere, including local/dev environments"*; kb-checker *"exposes no TCP/UDP ports. All communication is UDS-only."* Redis in its default configuration listens on a TCP port. Standing one up — even locally, even for dev — introduces exactly the network listener surface this system's design deliberately has zero of everywhere else. (Redis *can* be configured Unix-socket-only, which would sidestep the letter of this constraint, but that's a workaround for a store this repo has no other reason to run — see the latency/overhead point below, which still applies on top of this.)

Independent of the transport issue, it also loses Ray's in-memory/zero-copy latency advantage for this data — round-trips go to Redis instead of between actors, plus it's a new daemon to run, monitor, and secure that nothing else in this repo currently depends on. Note: Ray runs its own internal Redis-based GCS for cluster metadata — using that instance directly for application data is not advisable regardless of the above.

---

## Recommendation (proposed, not decided)

Split by data lifetime, and avoid introducing a new store where one already exists:

| State | Lifetime | Proposed mechanism |
|---|---|---|
| Vote tallies, in-flight jury quorum status | Round-scoped, small, disposable if lost | **Option A** — a `SwarmMemory` actor per `Judge`/round. If `Judge` dies mid-round, restarting the round is acceptable. |
| Threat history / agent reputation scores that should persist across rounds | Durable, needs to survive restarts | **`kb-control-plane`'s existing L1 `sync.Map`/L2 SQLite store** (per `ADR-1`), over the same UDS gRPC path `Executor` already uses to submit decisions. Option B is off the table entirely — see above. |

- Rationale: `Executor` (walkthrough §5C) already has a gRPC path back to the Go control plane over the UDS gateway (`/run/kb/kba.sock` per `kba_uds_binding_spec.md`; the walkthrough's own §5C names `/run/kb/kbd-grpc.sock`, worth reconciling with Karthik — likely the same socket under a different name in the two docs). Routing durable shared state through that existing UDS boundary keeps `kb-aads` state-management consistent with the rest of the system's storage design *and* its no-TCP-surface constraint, instead of adding a dependency (Redis) that's both undocumented elsewhere in this repo and architecturally disallowed as commonly deployed.

This is a design call with wire-path implications (`kb-aads` ↔ `kb-control-plane`), not just a `kb-aads`-internal implementation detail — flagging for Karthik's review before anything here is implemented.

---

## Open questions for Karthik

1. Does the current JJE design actually need cross-actor *mid-round* vote visibility (Option A's main justification), or does `Judge` collecting votes via `ray.get()` at the end of the round (as §5B already shows) cover the real requirement? If the latter, Option A may be unnecessary complexity for now.
2. Is persisting threat-confidence/reputation history across rounds in scope yet, or is that a later feature? If not yet needed, the durable-side recommendation above can wait.
3. If durable shared state is needed sooner than a `kb-control-plane` gRPC round-trip is convenient for, what's the fallback? Option B (Redis) is not a valid default here given the no-TCP-surface constraint (`kba_uds_binding_spec.md`, `kb-checker/README.md`) — any exception to that would need explicit sign-off from whoever owns that constraint, not a default in this doc.
4. Walkthrough §5C names the Executor's gRPC socket as `/run/kb/kbd-grpc.sock`, but `kba_uds_binding_spec.md` names the control plane's gRPC UDS as `/run/kb/kba.sock`. Worth confirming these refer to the same socket — if not, that's a separate discrepancy to flag against the walkthrough.

---

## Changelog

- **2026-07-24**: Initial proposal, raised as a gap against `ray-integration-walkthrough.md` §5/§6 — Plasma's immutability means no mechanism currently exists in the documented design for shared *mutable* swarm state, only fast message-passing.
