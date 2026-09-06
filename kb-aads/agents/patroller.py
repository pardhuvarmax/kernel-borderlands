import itertools

import ray

from .base_agent import BaseAgent, AgentRole

# Matches config/policy.yaml's `defaults.suspicious` (40.0) on the Go
# control-plane side — Patroller's own escalation threshold is a
# swarm-side mirror of the same concept (score at which a process is
# "worth a second look"), not the same enforced value; kept separate and
# configurable via config/agents.yaml's `patroller.suspicious_threshold`
# since the two systems can reasonably tune independently.
DEFAULT_SUSPICIOUS_THRESHOLD = 40.0


@ray.remote
class PatrollerAgent(BaseAgent):
    """
    Patroller agents monitor baseline process behavior and escalate to
    Hunter when a process's score crosses a threshold.

    Per marl/README.md's "RL scope" table, Patroller gets NO trained
    model — "rule-based orchestration," explicitly, unlike Jury/Healer/
    Containment. This is that rule: track the latest score per PID,
    dispatch to a Hunter (round-robin across whatever Hunter pool this
    Patroller was constructed with) the moment a PID crosses
    suspicious_threshold, using the exact ZONE_TRANSITION/SUSPICIOUS
    message shape agents/hunter.py's handle_message already listens for
    — no changes needed on the Hunter side.

    hunter_pool may be empty/None (e.g. in isolated unit tests, or a
    swarm configured with patroller > 0 but hunter == 0) — escalation is
    then a documented no-op (logged, not raised), same "degrade, don't
    crash" posture BaseAgent.process_messages already uses for a single
    bad message.
    """

    def __init__(self, agent_id: str, hunter_pool=None, suspicious_threshold: float = DEFAULT_SUSPICIOUS_THRESHOLD):
        super().__init__(agent_id, AgentRole.PATROLLER)
        self.monitored_pids = {}  # pid -> last-seen score
        self.hunter_pool = list(hunter_pool) if hunter_pool else []
        self.suspicious_threshold = suspicious_threshold
        self._escalated_pids = set()  # avoid re-escalating the same PID on every subsequent KB_EVENT
        self._hunter_cycle = itertools.cycle(self.hunter_pool) if self.hunter_pool else None

    async def tick(self):
        self.state.last_action = f"Monitoring {len(self.monitored_pids)} process(es), threshold={self.suspicious_threshold}"

    async def handle_message(self, message: dict):
        if message.get("type") != "KB_EVENT":
            return
        pid = message.get("pid")
        if pid is None:
            return
        score = float(message.get("score", 0.0))
        self.monitored_pids[pid] = score

        if score >= self.suspicious_threshold and pid not in self._escalated_pids:
            await self._escalate(pid, score)
        elif score < self.suspicious_threshold and pid in self._escalated_pids:
            # Score dropped back below threshold — allow a future
            # re-crossing to escalate again instead of being permanently
            # silenced for this PID.
            self._escalated_pids.discard(pid)

    async def _escalate(self, pid: int, score: float):
        self._escalated_pids.add(pid)
        self.state.last_action = f"Escalating PID {pid} (score={score:.1f}) to Hunter"
        if self._hunter_cycle is None:
            print(f"[{self.state.agent_id}] PID {pid} crossed threshold (score={score:.1f}) but no Hunter is configured — dropped")
            return
        hunter = next(self._hunter_cycle)
        await hunter.receive_message.remote({
            "type": "ZONE_TRANSITION",
            "to_zone": "SUSPICIOUS",
            "pid": pid,
            "score": score,
        })
