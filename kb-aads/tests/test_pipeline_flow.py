import os, sys, types
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pipeline.flow import Coalescer, IncidentGate, event_to_message, level_for, confidence_from


def ev(**kw):
    d = dict(pid=10, comm="x", event_type="process_state", score_delta=50.0, timestamp=1,
             metadata={"zone": "SUSPICIOUS", "uid": "0"})
    d.update(kw)
    return types.SimpleNamespace(**d)


def test_translate_process_state_and_zone_transition():
    m = event_to_message(ev())
    assert m["zone_id"] == 1 and m["uid"] == 0 and m["score"] == 50.0
    z = event_to_message(ev(event_type="zone_transition", metadata={"to_zone": "BORDERLANDS"}))
    assert z["zone_id"] == 2
    assert event_to_message(ev(event_type="other")) is None
    assert event_to_message(ev(pid=0)) is None


def test_coalescer_merges_and_keeps_spike():
    c = Coalescer(capacity=8)
    for s in (10, 90, 20):
        c.put(event_to_message(ev(score_delta=s)))
    assert len(c) == 1 and c.coalesced == 2
    assert c.drain(5)[0]["score"] == 90


def test_coalescer_sheds_lowest_score_first():
    c = Coalescer(capacity=3)
    for pid, s in [(1, 5), (2, 80), (3, 40), (4, 60)]:
        c.put(event_to_message(ev(pid=pid, score_delta=s)))
    assert c.dropped == 1 and {m["pid"] for m in c.drain(10)} == {2, 3, 4}
    assert c.high_water == 3


def test_gate_dedup_cooldown_and_cap():
    t = [0.0]
    g = IncidentGate(max_concurrent=2, cooldown_s=10, clock=lambda: t[0])
    assert g.try_admit(1) and not g.try_admit(1)
    assert g.try_admit(2) and not g.try_admit(3)
    g.release(1)
    assert not g.try_admit(1)  # cooldown
    t[0] = 11
    assert g.try_admit(1)
    assert g.refused == {"inflight": 1, "cooldown": 1, "saturated": 1}


def test_level_policy_never_terminates_outside_borderlands_or_low_conf():
    m = event_to_message(ev(metadata={"zone": "BORDERLANDS", "uid": "0"}, score_delta=90))
    assert level_for(m, confidence_from(m)) == 4
    assert level_for(m, 0.7) == 3
    assert level_for(m, 0.9, model_level=4) == 4
    s = event_to_message(ev())
    assert level_for(s, 0.9, model_level=4) == 3  # PPO cannot terminate a SUSPICIOUS pid
    safe = event_to_message(ev(metadata={"zone": "SAFE"}))
    assert level_for(safe, 0.9, model_level=3) == 0


def test_run_staged_retries_throttle_and_halts_on_refusal():
    from pipeline.flow import run_staged
    A = types.SimpleNamespace
    calls = []
    script = {"CGROUP": [A(success=False, message="agent x throttled, retry"), A(success=True, message="ok")],
              "SECCOMP": [A(success=True, message="ok")],
              "NAMESPACE": [A(success=False, message="sensor did not acknowledge")]}

    def submit(stage, pid, conf, auth):
        calls.append(stage)
        return script[stage].pop(0)

    r = run_staged(submit, 7, 4, 0.9, ["judge"], sleep=lambda s: None)
    assert r["applied"] == ["CGROUP", "SECCOMP"] and r["halted_at"] == "NAMESPACE"
    assert calls == ["CGROUP", "CGROUP", "SECCOMP", "NAMESPACE"]  # TERMINATE never attempted
