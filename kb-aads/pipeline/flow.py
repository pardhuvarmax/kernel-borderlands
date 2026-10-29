"""
Ray-free core of the live agent decision pipeline.

kbd StreamEvents -> IngestAgent -> Patroller -> Hunter -> Judge/Jury ->
Executor (staged containment) -> kbd SubmitAgentDecision.

Everything here is plain Python so it is unit-testable without a Ray
runtime. The agents are thin wrappers around it. Design rule (flood-
resilience): the swarm is advisory. kbd's own deterministic enforcement
(zone policy, CPM/CWP gates) never waits on any of this, so every queue
here is bounded and sheds load with accounting instead of blocking.
"""
import time
from collections import OrderedDict

ZONE_IDS = {"SAFE": 0, "SUSPICIOUS": 1, "BORDERLANDS": 2}
LEVEL_NAMES = ["NONE", "CGROUP", "SECCOMP", "NAMESPACE", "TERMINATE"]

# Highest level the swarm may reach on its own. TERMINATE needs kbd's
# 0.85 confidence gate AND the sensor's CPM/CWP ack, so it stays reachable,
# but only for BORDERLANDS with root + high confidence (see level_for).
MAX_AUTO_LEVEL = 4


def event_to_message(ev):
    """KBEvent proto (or equivalent object) -> agent message dict, or None.

    kbd emits event_type "process_state" (score in score_delta, zone/uid in
    metadata) and "zone_transition" (from/to zone in metadata). Anything
    else is ignored rather than guessed at.
    """
    et = getattr(ev, "event_type", "")
    md = dict(getattr(ev, "metadata", {}) or {})
    pid = int(getattr(ev, "pid", 0))
    if not pid or et not in ("process_state", "zone_transition"):
        return None
    score = float(getattr(ev, "score_delta", 0.0))
    if et == "zone_transition":
        zone = md.get("to_zone", "SAFE")
    else:
        zone = md.get("zone", "SAFE")
    return {
        "type": "KB_EVENT",
        "pid": pid,
        "comm": getattr(ev, "comm", ""),
        "score": score,
        "zone": zone,
        "zone_id": ZONE_IDS.get(zone, 0),
        "uid": int(md.get("uid", "-1") or -1),
        "event_kind": et,
        "ts": int(getattr(ev, "timestamp", 0)),
    }


class Coalescer:
    """Bounded latest-wins buffer keyed by PID.

    A flood of process_state updates for one PID collapses to one pending
    entry; a flood across many PIDs is capped at `capacity`, dropping the
    LOWEST-score entry first so the most dangerous processes survive.
    Every shed or merged event is counted, never silent.
    """

    def __init__(self, capacity=1024):
        self.capacity = capacity
        self._items = OrderedDict()
        self.received = 0
        self.coalesced = 0
        self.dropped = 0
        self.high_water = 0

    def __len__(self):
        return len(self._items)

    def put(self, msg):
        self.received += 1
        pid = msg["pid"]
        prev = self._items.pop(pid, None)
        if prev is not None:
            self.coalesced += 1
            # Keep the highest score seen while pending: a spike must not
            # be erased by a later quiet sample.
            if prev["score"] > msg["score"]:
                msg = dict(msg, score=prev["score"], zone=prev["zone"], zone_id=prev["zone_id"])
        self._items[pid] = msg
        if len(self._items) > self.capacity:
            victim = min(self._items, key=lambda p: self._items[p]["score"])
            del self._items[victim]
            self.dropped += 1
        self.high_water = max(self.high_water, len(self._items))

    def drain(self, n):
        out = []
        while self._items and len(out) < n:
            out.append(self._items.popitem(last=False)[1])
        return out

    def stats(self):
        return {"received": self.received, "coalesced": self.coalesced,
                "dropped": self.dropped, "pending": len(self), "high_water": self.high_water}


class IncidentGate:
    """Admission control for per-PID incidents: one in flight per PID, a
    cooldown after completion, and a global concurrency cap. A refused
    incident is counted by reason so overload is visible, not silent."""

    def __init__(self, max_concurrent=4, cooldown_s=30.0, clock=time.monotonic):
        self.max_concurrent = max_concurrent
        self.cooldown_s = cooldown_s
        self._clock = clock
        self._inflight = set()
        self._done_at = {}
        self.refused = {"inflight": 0, "cooldown": 0, "saturated": 0}
        self.admitted = 0
        self.high_water = 0

    def try_admit(self, pid):
        if pid in self._inflight:
            self.refused["inflight"] += 1
            return False
        if self._clock() - self._done_at.get(pid, -1e18) < self.cooldown_s:
            self.refused["cooldown"] += 1
            return False
        if len(self._inflight) >= self.max_concurrent:
            self.refused["saturated"] += 1
            return False
        self._inflight.add(pid)
        self.admitted += 1
        self.high_water = max(self.high_water, len(self._inflight))
        return True

    def release(self, pid):
        self._inflight.discard(pid)
        self._done_at[pid] = self._clock()
        if len(self._done_at) > 4096:  # bound memory
            cutoff = self._clock() - self.cooldown_s
            self._done_at = {p: t for p, t in self._done_at.items() if t > cutoff}

    def stats(self):
        return {"admitted": self.admitted, "refused": dict(self.refused),
                "inflight": len(self._inflight), "high_water": self.high_water}


def confidence_from(msg):
    """0..1 confidence kbd's 0.85 TERMINATE gate compares against. Derived
    from the EMA score (0..100) with a root bump; not a trained value."""
    c = min(max(msg["score"], 0.0), 100.0) / 100.0
    if msg.get("uid") == 0:
        c = min(1.0, c + 0.05)
    return round(c, 3)


def level_for(msg, confidence, model_level=None):
    """Containment level to stage up to. Uses the trained PPO level when
    one is supplied (capped), else a deterministic, documented fallback.
    SAFE never contains. Only BORDERLANDS can reach TERMINATE, and only at
    confidence >= 0.85, matching kbd's own gate."""
    if msg["zone_id"] == 0:
        return 0
    if model_level is not None:
        lvl = int(model_level)
    elif msg["zone_id"] == 2:
        lvl = 4 if confidence >= 0.85 else 3
    else:
        lvl = 1 if confidence < 0.6 else 2
    if lvl >= 4 and not (msg["zone_id"] == 2 and confidence >= 0.85):
        lvl = 3
    return max(0, min(lvl, MAX_AUTO_LEVEL))


def run_staged(submit, pid, target_level, confidence, authorized_by, sleep=time.sleep,
               pace_s=0.25, max_retries=3):
    """Escalate CGROUP -> SECCOMP -> NAMESPACE -> TERMINATE up to
    target_level, one stage at a time, stopping at the first refusal.

    `submit(action, pid, confidence, authorized_by)` returns an ack with
    .success/.message. kbd throttles each agent_id to one decision per
    200 ms, so stages are paced and a "throttled" reply is retried. A
    refusal (CPM/CWP gate, confidence gate, no sensor, unacknowledged) is
    NOT retried and halts the ladder: unknown enforcement status is never
    reported as success. Returns {"applied": [...], "halted_at": str|None,
    "message": str, "final_level": int}.
    """
    applied, halted, msg = [], None, ""
    for stage in LEVEL_NAMES[1:target_level + 1]:
        for attempt in range(max_retries + 1):
            ack = submit(stage, pid, confidence, authorized_by)
            if ack.success:
                applied.append(stage)
                msg = ack.message
                break
            msg = ack.message
            if "throttled" in msg and attempt < max_retries:
                sleep(pace_s)
                continue
            halted = stage
            break
        if halted:
            break
        sleep(pace_s)
    return {"applied": applied, "halted_at": halted, "message": msg,
            "final_level": len(applied)}
