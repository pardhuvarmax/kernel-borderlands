import asyncio

import ray

from .base_agent import BaseAgent, AgentRole
from comms.grpc_client import ControlPlaneClient

# Order matches kb.proto's ContainmentLevel enum (see agents/containment.py's
# LEVEL_NAMES) and the roadmap's "contain / isolate / eradicate" escalation
# framing (docs/development/control-aads/aads-intelligence-roadmap.md, line
# 62): CGROUP/SECCOMP = contain, NAMESPACE = isolate, TERMINATE = eradicate.
# Index 0 (NONE) has no stage — a squad is never commanded to enforce NONE.
ESCALATION_STAGES = ["CGROUP", "SECCOMP", "NAMESPACE", "TERMINATE"]


@ray.remote
class MilitiaSquadMemberAgent(BaseAgent):
    """
    One mechanical executor for exactly one containment stage.

    Per the roadmap's militia framing: "a squad of specialized, mechanical
    executors, each responsible for actually carrying out one stage of
    [the escalation] sequence... under one commanding decision — not each
    member independently deciding a level." This class holds no judgment
    at all — it only knows how to apply the single stage it was built for,
    via ControlPlaneClient.set_containment (the same live gRPC path
    ExecutorAgent uses for QUARANTINE, previously unused for granular
    per-level enforcement — see comms/grpc_client.py's set_containment).
    """

    def __init__(self, agent_id: str, stage: str, socket_path: str = "/run/kb/kba.sock"):
        if stage not in ESCALATION_STAGES:
            raise ValueError(f"MilitiaSquadMemberAgent: unknown stage {stage!r}, expected one of {ESCALATION_STAGES}")
        super().__init__(agent_id, AgentRole.MILITIA_MEMBER)
        self.stage = stage
        self.client = ControlPlaneClient(socket_path=socket_path)

    async def execute(self, pid: int, reason: str) -> dict:
        try:
            ack = await asyncio.to_thread(self.client.set_containment, pid=pid, level=self.stage, reason=reason)
            self.state.last_action = f"PID {pid} -> {self.stage} ({'ok' if ack.success else 'failed'})"
            return {"stage": self.stage, "pid": pid, "success": ack.success, "message": ack.message}
        except Exception as e:
            self.state.last_action = f"PID {pid} -> {self.stage} (error: {e})"
            return {"stage": self.stage, "pid": pid, "success": False, "message": str(e)}

    async def stop(self):
        self.client.close()
        await super().stop()


@ray.remote
class MilitiaSquadLeadAgent(BaseAgent):
    """
    Coordinator ("squad lead," per the roadmap's Judge-for-JJE analogy) for
    one containment escalation sequence against one PID.

    No model, ever — this is pure orchestration, same as Judge. Per the
    roadmap: the Containment RL policy (agents/containment.py) decides the
    target level; the squad lead's only job is executing every stage up to
    and including that target IN ORDER, one at a time, so stages can't race
    each other on the same PID (the roadmap's stated correctness concern —
    "N conflicting enforcement actions on one process" if members decided
    independently). Squad members are spawned dynamically per incident,
    mirroring consensus/jje.py's JudgeAgent spawning a fresh Jury pool per
    consensus round rather than keeping one running permanently.

    Escalation stops early if a stage reports failure (success=False) —
    there is no defined recovery/retry policy for a failed intermediate
    stage yet; this is a real, undesigned gap (same posture as Healer's
    documented RL gap), not a silent swallow. Callers get the full stage
    report list either way and can decide what a partial escalation means.
    """

    def __init__(self, agent_id: str, socket_path: str = "/run/kb/kba.sock", squad_member_cls=None, registry=None):
        super().__init__(agent_id, AgentRole.MILITIA_LEAD)
        self.socket_path = socket_path
        # Injectable for testing (a fake member class with deterministic
        # execute() results) without touching production wiring — mirrors
        # JudgeAgent's jury_agent_cls parameter.
        self.squad_member_cls = squad_member_cls or MilitiaSquadMemberAgent
        # Optional swarm/registry.py SwarmRegistry handle — if given, each
        # dynamically-spawned member is registered so JJE courthouse
        # oversight (consensus/jje.py) can reach it later. None in tests
        # that don't need registry lookups.
        self.registry = registry

    async def command_squad(self, pid: int, target_level: int, reason: str) -> dict:
        """
        target_level: 1-4, matching ContainmentAgent.decide()'s "level"
        (LEVEL_NAMES index) — 0 (NONE) is invalid here, since a squad is
        never commanded when no containment is warranted.
        """
        if not (1 <= target_level <= len(ESCALATION_STAGES)):
            raise ValueError(f"MilitiaSquadLeadAgent: target_level must be 1-{len(ESCALATION_STAGES)}, got {target_level}")

        stages = ESCALATION_STAGES[:target_level]
        self.state.last_action = f"Commanding squad for PID {pid}: {stages}"

        reports = []
        for i, stage in enumerate(stages):
            member_id = f"{self.state.agent_id}-member-{i}-{stage.lower()}"
            member = self.squad_member_cls.remote(member_id, stage, self.socket_path)
            if self.registry is not None:
                self.registry.register.remote(member_id, AgentRole.MILITIA_MEMBER.value, member)
            result = await member.execute.remote(pid, reason)
            reports.append(result)
            if not result["success"]:
                self.state.last_action = f"PID {pid} squad halted at {stage} (failure)"
                break
        else:
            self.state.last_action = f"PID {pid} squad completed through {stages[-1]}"

        return {"pid": pid, "target_level": target_level, "stages": reports}

    async def handle_message(self, message: dict):
        if message.get("type") != "CONTAIN_SQUAD":
            return
        await self.command_squad(
            pid=message["pid"],
            target_level=message["target_level"],
            reason=message.get("reason", ""),
        )
