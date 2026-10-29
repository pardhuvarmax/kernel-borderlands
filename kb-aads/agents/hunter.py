from .base_agent import BaseAgent, AgentRole
import asyncio
import ray
from pipeline.flow import confidence_from, IncidentGate


@ray.remote
class HunterAgent(BaseAgent):
    """
    Hunter agents investigate suspicious processes.
    Activated when Patroller escalates a PID that crossed the suspicious
    threshold (fed by the live ingest path, see agents/ingest.py).

    Investigation: re-read the PID's CURRENT state from kbd (evidence that
    the process still exists and is still hot, not the stale event that
    triggered us), derive a 0-1 confidence, optionally ask a Containment
    agent for the PPO level, then submit to the Judge. Incidents are
    deduplicated per PID with a cooldown and bounded concurrency so an
    alert flood cannot fan out into unbounded Jury rounds. A Judge failure
    or timeout is logged and counted; it never touches kbd's own
    deterministic enforcement.
    """

    def __init__(self, agent_id: str, judge=None, containment_pool=None, state_socket=None, state_client=None,
                 max_concurrent: int = 4, cooldown_s: float = 30.0, deadline_s: float = 15.0,
                 use_learned_policy: bool = False):
        super().__init__(agent_id, AgentRole.HUNTER)
        self.investigations = {}
        self.judge = judge
        self.containment_pool = list(containment_pool or [])
        # Own unary channel, built here (a gRPC channel cannot be pickled into
        # the actor). None = skip the evidence refresh (unit tests).
        if state_client is None and state_socket:
            from comms.grpc_client import ControlPlaneClient
            state_client = ControlPlaneClient(socket_path=state_socket)
        self._state_client = state_client
        self.gate = IncidentGate(max_concurrent=max_concurrent, cooldown_s=cooldown_s)
        self.deadline_s = deadline_s
        # The trained PPO policies take a scenario-derived `event_type` as
        # input (marl/README.md: each attack scenario got its own code from
        # the labels). kbd's live events carry no such field, so fed real
        # data they answer ALLOW/NONE for everything (verified: score 92,
        # root, BORDERLANDS -> ALLOW). Off by default: Jury then uses its
        # confidence-threshold fallback and the level comes from
        # pipeline.flow.level_for. Turn on only after retraining on
        # sensor-derived features.
        self.use_learned_policy = use_learned_policy
        self.outcomes = {"contain": 0, "allow": 0, "timeout": 0, "error": 0, "stale": 0, "no_judge": 0}
        self._tasks = set()

    async def tick(self):
        self.state.last_action = f"Scanning for threats ({len(self.investigations)} case(s))"

    async def handle_message(self, message: dict):
        if message.get("type") == "ZONE_TRANSITION" and message.get("to_zone") == "SUSPICIOUS":
            await self.investigate(message["pid"], message["score"], message)

    async def investigate(self, pid: int, score: float, message: dict = None):
        if not self.gate.try_admit(pid):
            return
        # Run off the message loop so a slow Judge round never blocks intake.
        task = asyncio.ensure_future(self._run(pid, score, message or {}))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _evidence(self, pid, message):
        msg = {"pid": pid, "score": float(message.get("score", 0.0)),
               "zone": message.get("zone", "SUSPICIOUS"), "zone_id": int(message.get("zone_id", 1)),
               "uid": int(message.get("uid", -1)), "comm": message.get("comm", "")}
        if self._state_client is not None:
            try:
                ps = await asyncio.to_thread(self._state_client.get_process_state, pid)
            except Exception:
                return None  # process gone / untracked: nothing to contain
            msg.update(score=float(ps.score), zone_id=int(ps.zone), uid=int(ps.uid), comm=ps.comm,
                       zone=["SAFE", "SUSPICIOUS", "BORDERLANDS"][int(ps.zone)])
        return msg

    async def _run(self, pid, score, message):
        self.state.last_action = f"Investigating PID {pid}"
        try:
            ev = await self._evidence(pid, message)
            if ev is None or ev["zone_id"] == 0:
                self.outcomes["stale"] += 1  # exited, or already back to SAFE
                return
            conf = confidence_from(ev)
            self.investigations[pid] = {"score": ev["score"], "confidence": conf, "zone": ev["zone"]}
            if self.judge is None:
                self.outcomes["no_judge"] += 1
                return
            payload = dict(ev, confidence=conf)
            if self.use_learned_policy:
                payload["obs"] = {"score": ev["score"], "zone": ev["zone_id"],
                                  "uid_is_root": 1 if ev["uid"] == 0 else 0,
                                  "score_delta": 0.0, "event_type": 0}
            if self.use_learned_policy and self.containment_pool:
                try:
                    d = await asyncio.wait_for(
                        self.containment_pool[pid % len(self.containment_pool)].decide.remote(payload["obs"]), 3.0)
                    if d.get("model_loaded"):
                        payload["model_level"] = d["level"]
                except Exception:
                    pass  # advisory; fall back to deterministic level
            out = await asyncio.wait_for(self.judge.coordinate_consensus.remote(payload), self.deadline_s)
            key = (out or {}).get("decision", "error")
            self.outcomes[key if key in self.outcomes else "error"] += 1
            self.state.last_action = f"PID {pid}: {key}"
        except asyncio.TimeoutError:
            self.outcomes["timeout"] += 1
        except Exception as e:  # noqa: BLE001 - agent must not die on one bad incident
            self.outcomes["error"] += 1
            self.state.error_count += 1
            print(f"[{self.state.agent_id}] investigation of PID {pid} failed: {e}", flush=True)
        finally:
            self.gate.release(pid)

    def get_stats(self) -> dict:
        return {"gate": self.gate.stats(), "outcomes": dict(self.outcomes),
                "policy_mode": "learned" if self.use_learned_policy else "deterministic"}
