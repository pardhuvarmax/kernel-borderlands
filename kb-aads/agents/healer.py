import ray

from .base_agent import BaseAgent, AgentRole

# Matches config/policy.yaml's `defaults.suspicious` (40.0) posture: a
# process must have decayed well BELOW the suspicious floor, not just
# under it, before Healer will even consider recommending restore.
DEFAULT_SAFE_SCORE_THRESHOLD = 20.0
# Minimum ticks (BaseAgent.start()'s loop increments state.uptime once
# per ~1s iteration) a PID must have been under containment before
# restore is considered at all, regardless of how quickly its score
# recovers — a process that looks safe seconds after containment is more
# likely a noisy signal than a genuinely resolved threat.
DEFAULT_MIN_CONTAINMENT_TICKS = 60


@ray.remote
class HealerAgent(BaseAgent):
    """
    Healer agents decide whether a contained process is safe to restore.

    Per docs/development/control-aads/aads-intelligence-roadmap.md's
    per-agent table, Healer is RL-scoped in the DESIGN ("a bounded
    decision — restore vs. keep contained — with a clean reward...
    learnable from the same Phase 0/6 labeled-outcome pipeline"). It is
    NOT RL-trained here, and that's a stated, real gap, not an oversight:
    Phase 0's dataset (scripts/dataset/label.py) has attack-CATEGORY
    ground truth (used by Containment/Jury's training), not
    restore-OUTCOME ground truth ("was un-containing this PID actually
    safe N minutes later?") — that requires the Phase 6 analyst-feedback
    loop, which marl/README.md's own Training Pipeline section says is
    "still undesigned." Training on anything else here would mean
    fabricating reward labels this system has no real basis for, which is
    worse than an honest rule-based decision.

    So: this is a genuine rule-based implementation (not a stub) using
    the two hard requirements Karthik's own reward description already
    implies as prerequisites for restore ("correct restore = good,
    restoring a real threat = bad" only makes sense to even ask once
    enough time has passed AND the process's own signal has recovered) —
    conservative by construction: any missing/ambiguous signal defaults
    to KEEP_CONTAINED, never RESTORE.
    """

    def __init__(self, agent_id: str, min_containment_ticks: int = DEFAULT_MIN_CONTAINMENT_TICKS,
                 safe_score_threshold: float = DEFAULT_SAFE_SCORE_THRESHOLD):
        super().__init__(agent_id, AgentRole.HEALER)
        self.min_containment_ticks = min_containment_ticks
        self.safe_score_threshold = safe_score_threshold
        self._recovery_count = 0

    async def tick(self):
        self.state.last_action = f"Monitoring recovery tasks ({self._recovery_count} decided so far)"

    async def handle_message(self, message: dict):
        if message.get("type") != "RECOVER":
            return
        pid = message.get("pid")
        decision = self.decide(message)
        self._recovery_count += 1
        self.state.last_action = f"PID {pid} -> {decision}"
        print(f"[{self.state.agent_id}] {self.state.last_action}", flush=True)

    def decide(self, message: dict) -> str:
        """
        message: {"pid": int, "zone": int (0=SAFE/1=SUSPICIOUS/2=BORDERLANDS),
                  "score": float, "ticks_contained": int}
        matching ZoneTransitionMsg/ProcessStateMsg's wire-derived shape
        (kb-control-plane/internal/ipc/wire.go) plus the containment
        duration a caller must compute and supply — Healer does not track
        containment start times itself, since it has no independent view
        of when kbd actually applied containment (that's kb-control-
        plane's audit log, not something to duplicate/guess here).

        Any missing field defaults to the least permissive interpretation
        (zone treated as not-SAFE, score treated as max, ticks_contained
        treated as 0) so an incomplete message can never accidentally
        produce RESTORE.
        """
        zone = message.get("zone", 2)  # default: BORDERLANDS (worst case)
        score = message.get("score", 100.0)
        ticks_contained = message.get("ticks_contained", 0)

        if zone == 0 and score < self.safe_score_threshold and ticks_contained >= self.min_containment_ticks:
            return "RESTORE"
        return "KEEP_CONTAINED"
