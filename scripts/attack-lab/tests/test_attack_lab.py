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


def test_matched_pairs_use_the_same_binary_so_a_model_cannot_separate_them_by_name():
    """The first corpus' hard negatives used different tools from the attacks, which lets a
    model separate them by process name alone. Each pair here shares its tool and differs
    only in context."""
    src = open(os.path.join(LAB, "payloads.py")).read()
    def body(fn):
        a = src.index(f"def {fn}(")
        return src[a:src.index("\ndef ", a + 1)]
    for attack, benign, tool in (("exfil_staging", "backup_etc_workload", '"tar"'),
                                 ("credential_dump", "credential_audit_workload", '"/etc/shadow"')):
        assert tool in body(attack) and tool in body(benign), f"{attack} / {benign} must share {tool}"
    kinds = {n: payloads.SCENARIOS[n][0] for n in ("exfil_staging", "credential_dump", "benign_backup_etc", "benign_credential_audit")}
    assert kinds == {"exfil_staging": "attack", "credential_dump": "attack",
                     "benign_backup_etc": "benign", "benign_credential_audit": "benign"}
    # the attack halves of the pairs differ from the benign halves by an outbound connection
    assert "connect_ex" in body("exfil_staging") and "connect_ex" not in body("backup_etc_workload")
    assert "connect_ex" in body("credential_dump") and "connect_ex" not in body("credential_audit_workload")


def test_network_using_benign_pair_members_read_secrets_and_connect_like_the_attacks():
    """A 'secret read + network in one tree' rule must meet benign work that does both, or
    it looks better than it is. These benign scenarios read /etc/shadow AND really connect
    and move bytes (to a loopback sink), matched to the attacks by tool."""
    src = open(os.path.join(LAB, "payloads.py")).read()
    def body(fn):
        a = src.index(f"def {fn}(")
        return src[a:src.index("\ndef ", a + 1)]
    b1, b2 = body("backup_remote_workload"), body("credential_report_workload")
    assert '"tar"' in b1 and "/etc" in b1 and "_upload(" in b1          # tar of /etc, then a real upload
    assert '"/etc/shadow"' in b2 and "_upload(" in b2                    # shadow read, then a real upload
    assert "127.0.0.3" in b1 and "127.0.0.3" in b2                       # loopback only
    assert payloads.SCENARIOS["benign_backup_remote"][0] == "benign"
    assert payloads.SCENARIOS["benign_credential_report"][0] == "benign"
    s1 = payloads._Sink("127.0.0.1"); s1.start()
    try:
        import tempfile
        f = tempfile.NamedTemporaryFile(delete=False); f.write(b"x" * 100000); f.close()
        assert payloads._upload("127.0.0.1", s1.port, f.name) == 100000
        deadline = time.time() + 3
        while time.time() < deadline and s1.received < 100000:
            time.sleep(0.05)
        assert s1.received == 100000
        os.unlink(f.name)
    finally:
        s1.close()
    with pytest.raises(ValueError):
        payloads._Sink("8.8.8.8")


def test_sensor_exit_state_is_read_from_the_service_environment(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda _: "/bin/systemctl")
    for env, want in (("KB_SENSOR_EXIT_STATE=all", "all"), ("FOO=1 KB_SENSOR_EXIT_STATE=off", "off"),
                      ("KB_SENSOR_EXIT_STATE=weird", "anomalous"), ("", "anomalous")):
        monkeypatch.setattr(runner, "sh", lambda *_a, _e=env, **_k: _e)
        assert runner.sensor_exit_state() == want
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    assert runner.sensor_exit_state() is None


def test_sensor_bytes_sent_is_read_from_the_service_environment(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda _: "/bin/systemctl")
    for env, want in (("KB_BYTES_SENT=1", True), ("FOO=1 KB_BYTES_SENT=1", True), ("KB_BYTES_SENT=0", False), ("", False)):
        monkeypatch.setattr(runner, "sh", lambda *_a, _e=env, **_k: _e)
        assert runner.sensor_bytes_sent() is want
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    assert runner.sensor_bytes_sent() is None


# ---- real-byte scenarios (added with plan Workstream D) -------------------------------------
import payloads as _pl  # noqa: E402  (already importable via sys.path above)

REAL_BYTE_SCENARIOS = {
    # name: (kind, family, must_send_bytes)
    "exfil_small_real": ("attack", "exfil_small"), "exfil_bulk_real": ("attack", "exfil_bulk"),
    "exfil_slow_real": ("attack", "exfil_slow"), "c2_beacon_real": ("attack", "c2_real"),
    "benign_backup_bulk": ("benign", "backup_bulk"), "benign_heartbeat_real": ("benign", "heartbeat"),
    "benign_telemetry_small": ("benign", "telemetry_small"),
    "exfil_via_known_host_real": ("attack", "exfil_known"), "benign_backup_new_host": ("benign", "backup_new"),
    "benign_telemetry_new_host": ("benign", "telemetry_new"),
    "c2_beacon_via_known_host_real": ("attack", "c2_known"), "benign_heartbeat_new_host": ("benign", "heartbeat_new"),
}


def test_real_byte_scenarios_are_registered_with_the_right_kind_and_family():
    for name, (kind, family) in REAL_BYTE_SCENARIOS.items():
        assert _pl.SCENARIOS[name][0] == kind and _pl.SCENARIOS[name][1] == family
    # every attack has a benign counterpart in the same size/interval class
    assert {"benign_backup_bulk", "benign_heartbeat_real", "benign_telemetry_small"} <= set(_pl.SCENARIOS)


def _fake_run(cmd, **kw):
    """Stand in for sudo/tar/uname/df: create the archive tar would have written, or some stdout."""
    if "tar" in cmd:
        out = cmd[cmd.index("tar") + 2]
        with open(out, "wb") as f:
            f.write(b"A" * 3072)
    out = kw.get("stdout")
    if hasattr(out, "write"):   # a real subprocess writes bytes whatever the handle's mode; the stub must match the handle
        out.write(b"stub output\n" if "b" in getattr(out, "mode", "") else "stub output\n")
    return 0


@pytest.mark.parametrize("name", sorted(REAL_BYTE_SCENARIOS))
def test_real_byte_scenarios_really_send_bytes_over_loopback(name, tmp_path, monkeypatch):
    import random
    monkeypatch.setattr(_pl, "run", _fake_run)
    monkeypatch.setattr(_pl, "BULK_MIB", (1, 1))
    monkeypatch.setattr(_pl, "SLOW_SENDS", 2)
    monkeypatch.setattr(_pl, "BEACONS", 3)
    monkeypatch.setattr(_pl.time, "sleep", lambda _s: None)
    log = []
    act = lambda action, malicious=False, **kw: log.append({"action": action, "malicious": malicious, **kw})  # noqa: E731
    _pl.SCENARIOS[name][2](str(tmp_path), random.Random(1), act)
    kind = REAL_BYTE_SCENARIOS[name][0]
    sent = sum(r.get("bytes", 0) for r in log)
    if name in ("c2_beacon_real", "benign_heartbeat_real", "c2_beacon_via_known_host_real", "benign_heartbeat_new_host"):
        assert any(r["action"] in ("beacon", "heartbeat", "beacon_via_trusted_host", "heartbeat_to_new_host") for r in log)   # beacons log the check-in, bytes are on the wire
    else:
        assert sent > 0, f"{name} logged no bytes sent: {log}"
    if kind == "attack":
        assert all(r["malicious"] for r in log if r["action"] in ("send_out", "beacon", "beacon_via_trusted_host"))
    else:
        assert not any(r["malicious"] for r in log)


def test_scenario_groups_split_legacy_and_real_bytes():
    g = _pl.GROUPS
    assert len(g["legacy"]) == 18 and len(g["real_bytes"]) == 7 and len(g["dest_mix"]) == 5
    assert set(g["legacy"]) | set(g["v2"]) == set(g["all"]) and not set(g["legacy"]) & set(g["v2"])


def test_destination_mix_breaks_the_address_split_between_attack_and_benign():
    """known_destinations lists KNOWN_HOSTS: some attack must go to a listed host and some benign work
    to an unlisted one, otherwise dest_known would separate the classes by construction."""
    import re
    src = open(os.path.join(LAB, "payloads.py")).read()
    attack_src = src[src.index("def exfil_via_known_host_real"):src.index("def backup_new_host_workload")]
    benign_src = src[src.index("def backup_new_host_workload"):src.index("SCENARIOS = {")]
    assert '"127.0.0.3"' in attack_src and "NEW_HOSTS" in benign_src
    assert not set(_pl.KNOWN_HOSTS) & set(_pl.NEW_HOSTS)
    for h in _pl.KNOWN_HOSTS + _pl.NEW_HOSTS:
        _pl.assert_loopback(h)
