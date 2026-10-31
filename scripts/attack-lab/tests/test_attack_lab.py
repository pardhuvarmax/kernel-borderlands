import json, os, re, subprocess, sys, time, types
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, LAB)
import labeling, payloads, runner
from capture import Capture


def test_every_scenario_is_labelled_and_covers_both_classes():
    kinds = {k for k, *_ in payloads.SCENARIOS.values()}
    assert kinds == {"attack", "benign"}
    # hard negatives that touch the same files/privilege paths as the attacks must exist
    assert "benign_admin_privileged" in payloads.SCENARIOS
    assert {"credential_access", "privilege_escalation", "process_injection", "network_c2",
            "memory_exploit", "evasion_slow"} <= set(payloads.SCENARIOS)


def test_payloads_contain_no_non_loopback_addresses():
    src = open(os.path.join(LAB, "payloads.py")).read()
    for ip in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", src):
        assert ip.startswith("127."), f"payloads.py references non-loopback address {ip}"
    with pytest.raises(ValueError):
        payloads.assert_loopback("8.8.8.8")
    with pytest.raises(ValueError):
        payloads.assert_loopback("192.0.2.1")
    payloads.assert_loopback("127.0.0.3")


def test_runner_refuses_without_ack_and_as_root():
    r = subprocess.run([sys.executable, os.path.join(LAB, "runner.py"), "--scenarios", "benign_idle"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "--ack-isolated" in r.stderr


def test_plan_is_seeded_shuffled_and_complete():
    a = runner.build_plan(["credential_access", "benign_idle"], 3, 7)
    b = runner.build_plan(["credential_access", "benign_idle"], 3, 7)
    assert a == b and len(a) == 6
    assert [x[0] for x in a] != sorted(x[0] for x in a) or len({x[2] for x in a}) == 6


def test_tree_watcher_finds_children_including_short_lived():
    p = subprocess.Popen(["sh", "-c", "sleep 2 & sleep 2; wait"], start_new_session=True)
    w = runner.TreeWatcher(p.pid)
    w.start()
    time.sleep(0.8)
    w.stop()
    p.wait()
    assert p.pid in w.pids and len(w.pids) >= 2


def ex(i, fam, kind="attack", pids=(), start=0, end=10**9):
    return {"execution_id": f"e{i}", "family": fam, "kind": kind, "pids": list(pids),
            "start_ns": start, "end_ns": end, "host": "h"}


def test_labeling_attributes_by_pid_and_time_and_marks_background():
    execs = [ex(1, "credential_access", pids=[100, 101], start=1000, end=2000)]
    events = [
        {"pid": 100, "recv_ns": 1500}, {"pid": 101, "recv_ns": 2000 + labeling.SETTLE_NS},
        {"pid": 100, "recv_ns": 9_000_000_000},      # same pid, after the window: pid reuse
        {"pid": 555, "recv_ns": 1500},               # unrelated process during the attack
        {"gap": True, "recv_ns": 1600},
    ]
    out = list(labeling.label_events(events, execs))
    assert [(o[0]["pid"], o[1] is not None, o[2]) for o in out] == [
        (100, True, True), (101, True, True), (100, False, False), (555, False, False)]
    assert len(labeling.gaps_in(events, 1000, 2000)) == 1


def test_split_is_by_execution_holds_out_families_and_never_leaks():
    execs = [ex(i, fam) for i, fam in enumerate(
        ["credential_access"] * 5 + ["network_c2"] * 5 + ["evasion"] * 4 + ["web"] * 6)]
    train, test = labeling.split_executions(execs, holdout_families=["evasion"], test_frac=0.4, seed=1)
    assert labeling.assert_no_leakage(train, test)
    assert {e["family"] for e in test if e["family"] == "evasion"} and \
        not [e for e in train if e["family"] == "evasion"]          # held-out family never trains
    for fam in ("credential_access", "network_c2", "web"):
        assert [e for e in train if e["family"] == fam] and [e for e in test if e["family"] == fam]
    assert len(train) + len(test) == len(execs)
    # deterministic
    assert labeling.split_executions(execs, ["evasion"], 0.4, 1) == (train, test)
    with pytest.raises(AssertionError):
        labeling.assert_no_leakage(train, train[:1])


class FakeClient:
    def __init__(self, events, fail_first=False):
        self.events, self.fail_first, self.calls = events, fail_first, 0
    def stream_events(self, types_):
        self.calls += 1
        if self.fail_first and self.calls == 1:
            raise ConnectionError("down")
        return iter(self.events)
    def close(self): pass


def test_capture_writes_events_and_records_a_gap_marker_on_disconnect(tmp_path):
    ev = types.SimpleNamespace(pid=7, ppid=1, comm="x", event_type="process_state", score_delta=3.0,
                               timestamp=5, metadata={"feature_schema": "1"})
    holder = {"n": 0}
    def factory():
        holder["n"] += 1
        return FakeClient([ev], fail_first=holder["n"] == 1)
    out = tmp_path / "e.jsonl"
    cap = Capture(str(out), client_factory=factory)
    import threading
    cap._thread = threading.Thread(target=cap._run, daemon=True)
    cap.connected.set()
    cap._thread.start()
    deadline = time.time() + 5
    while time.time() < deadline and cap.count < 1:
        time.sleep(0.05)
    cap.stop()
    lines = [json.loads(l) for l in out.read_text().splitlines()]
    assert any(l.get("gap") for l in lines), "disconnect must leave a gap marker"
    assert any(l.get("pid") == 7 and l["metadata"]["feature_schema"] == "1" for l in lines)


def test_capture_start_fails_fast_when_the_channel_never_becomes_ready(tmp_path):
    grpc = pytest.importorskip("grpc")

    class DeadClient:
        channel = grpc.insecure_channel("unix:///nonexistent/kba.sock")
        def stream_events(self, t): raise AssertionError("must not stream before ready")
        def close(self): pass

    cap = Capture(str(tmp_path / "e.jsonl"), client_factory=DeadClient)
    import threading
    cap._thread = threading.Thread(target=cap._run, daemon=True)
    cap._thread.start()
    assert not cap.connected.wait(5.0), "a dead socket must not be reported as connected"
    cap.stop()


def test_audit_attribution_by_pid_and_window_includes_would_contain():
    ex_ = {"pids": [10, 11], "start_ns": 1_000_000_000_000, "end_ns": 2_000_000_000_000}
    entries = [
        {"ts_ns": 1_500_000_000_000, "action": "OBSERVE_ONLY_WOULD_CGROUP_THROTTLE", "subject": "pid=10 comm=x", "actor": "SYSTEM_AUTO", "reason": ""},
        {"ts_ns": 1_500_000_000_000, "action": "CGROUP_THROTTLE", "subject": "pid=999 comm=other", "actor": "SYSTEM_AUTO", "reason": ""},
        {"ts_ns": 9_000_000_000_000, "action": "CGROUP_THROTTLE", "subject": "pid=10 comm=x", "actor": "SYSTEM_AUTO", "reason": ""},
    ]
    got = runner.audit_for_execution(entries, ex_)
    assert [g["action"] for g in got] == ["OBSERVE_ONLY_WOULD_CGROUP_THROTTLE"]
    assert runner.audit_for_execution(None, ex_) == []


def test_runner_refuses_when_not_observe_only(monkeypatch, capsys):
    monkeypatch.setattr(runner, "kbd_observe_only", lambda: False)
    monkeypatch.setattr(sys, "argv", ["runner.py", "--ack-isolated", "--scenarios", "benign_idle"])
    assert runner.main() == 2
    assert "observe-only" in capsys.readouterr().err


def test_expand_pids_recovers_short_lived_children_through_ppid_chains():
    ex_ = {"execution_id": "e", "root_pid": 100, "pids": [100], "start_ns": 1000, "end_ns": 5000, "kind": "attack", "family": "f", "host": "h"}
    events = [
        {"pid": 101, "ppid": 100, "recv_ns": 1500, "comm": "sudo"},     # child the poll missed
        {"pid": 102, "ppid": 101, "recv_ns": 1600, "comm": "cat"},      # grandchild, linked through 101
        {"pid": 200, "ppid": 1,   "recv_ns": 1500, "comm": "systemd"},  # unrelated
        {"pid": 103, "ppid": 100, "recv_ns": 9_000_000_000_000, "comm": "late"},  # after the window
        {"pid": 104, "ppid": 100, "recv_ns": 1700, "comm": "zt"},
        {"pid": 105, "ppid": 0,   "recv_ns": 1700, "comm": "zone_transition_no_ppid"},
        {"gap": True, "recv_ns": 1800},
    ]
    out = labeling.expand_pids(ex_, events)
    assert out["pids"] == [100, 101, 102, 104] and out["pids_from_events"] == [101, 102, 104]
    assert out["pids_polled"] == [100] and ex_["pids"] == [100]       # input is not mutated
    # and the attribution now picks the grandchild up
    labelled = [(e["pid"], hit is not None) for e, hit, _ in labeling.label_events(events, [out])]
    assert (102, True) in labelled and (200, False) in labelled
