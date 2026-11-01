import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, LAB)
import labeling, lidds_runner as lr


def fake_lidds(tmp_path, names=("CVE-2014-0160", "ZipSlip")):
    for n in names:
        d = tmp_path / "scenarios" / n
        d.mkdir(parents=True)
        (d / "main.py").write_text("")
    (tmp_path / "scenarios" / "check_recordings.py").write_text("")
    return str(tmp_path)


def test_lists_only_scenario_folders_with_main_py(tmp_path):
    assert lr.list_scenarios(fake_lidds(tmp_path)) == ["CVE-2014-0160", "ZipSlip"]
    assert lr.list_scenarios(str(tmp_path / "missing")) == []


def test_plan_is_seeded_shuffled_and_covers_both_modes():
    a = lr.build_plan(["A", "B"], ["normal", "exploit"], 3, 5)
    assert a == lr.build_plan(["A", "B"], ["normal", "exploit"], 3, 5)
    assert len(a) == 12 and {m for _, m, _, _ in a} == {"normal", "exploit"}


def test_commands_for_both_modes():
    assert lr.command_for(lr.DEFAULT_TEMPLATE, "python3.7", "normal", 60) == \
        ["sudo", "-n", "python3.7", "main.py", "1", "60", "0"]
    assert lr.command_for(lr.DEFAULT_TEMPLATE, "python3.7", "exploit", 60) == \
        ["sudo", "-n", "python3.7", "main.py", "1", "-1", "1"]


def test_container_roles_and_victim_override():
    assert lr.classify_role("cve-2014-0160_victim", "lidds/heartbleed") == "victim"
    assert lr.classify_role("cve-2014-0160_exploit", "lidds/exploit") == "exploit"
    assert lr.classify_role("normal_client_3", "lidds/normal") == "normal"
    assert lr.classify_role("db", "mysql:5.5") == "unknown"
    assert lr.classify_role("db", "mysql:5.5", victim_match="mysql") == "victim"


def test_pids_found_by_cgroup_membership(tmp_path):
    cid = "a" * 64
    for pid, cg in ((10, f"0::/system.slice/docker-{cid}.scope"), (11, f"12:pids:/docker/{cid}"),
                    (12, "0::/user.slice/session-1.scope")):
        (tmp_path / str(pid)).mkdir()
        (tmp_path / str(pid) / "cgroup").write_text(cg + "\n")
    (tmp_path / "self").mkdir()
    assert lr.pids_in_container(cid, proc_root=str(tmp_path)) == {10, 11}


def test_docker_output_parsing():
    rows = lr.parse_docker_ps("abc\tvictim\timg:1\n\nbad line\ndef\texploit\timg:2\n")
    assert [r["id"] for r in rows] == ["abc", "def"]
    import calendar
    base = calendar.timegm((2026, 11, 1, 22, 58, 41)) * 10**9
    assert lr.parse_started_at("2026-11-01T22:58:41.123456789Z") == base + 123456789
    assert lr.parse_started_at("2026-11-01T22:58:41.5Z") == base + 500000000
    assert lr.parse_started_at("2026-11-01T22:58:41Z") == base
    assert lr.parse_started_at("0001-01-01T00:00:00Z") is not None
    assert lr.parse_started_at("garbage") is None


def containers():
    return [{"id": "v", "name": "x_victim", "image": "i", "role": "victim", "host_pid": 500, "started_ns": 100},
            {"id": "e", "name": "x_exploit", "image": "i", "role": "exploit", "host_pid": 600, "started_ns": 250}]


def test_label_record_uses_victim_root_and_exploit_start():
    rec = lr.label_record("R", "ZipSlip", "exploit", 2, 9, "h", 42, 50, 900, containers(),
                          {"victim": {500, 501}, "exploit": {600}}, 0, False)
    assert rec["kind"] == "attack" and rec["family"] == "lidds_ZipSlip"
    assert rec["root_pid"] == 500 and rec["runner_pid"] == 42
    assert rec["pids"] == [500, 501] and rec["victim_found"]
    assert 600 not in rec["pids"] and rec["pids_by_role"]["exploit"] == [600]
    assert rec["first_malicious_ns"] == 250 and rec["first_malicious_source"] == "exploit_container_start"
    normal = lr.label_record("R", "ZipSlip", "normal", 0, 9, "h", 42, 50, 900, containers()[:1],
                             {"victim": {500}}, 0, False)
    assert normal["kind"] == "benign" and normal["first_malicious_ns"] is None


def test_expand_pids_does_not_pull_in_the_runner_tree():
    rec = lr.label_record("R", "ZipSlip", "exploit", 0, 1, "h", 42, 0, 10**9, containers(),
                          {"victim": {500}}, 0, False)
    events = [{"pid": 43, "ppid": 42, "recv_ns": 10},      # LID-DS framework under the runner
              {"pid": 777, "ppid": 500, "recv_ns": 20}]    # shell spawned inside the victim
    out = labeling.expand_pids(rec, events)
    assert 777 in out["pids"] and 43 not in out["pids"]


def test_missing_victim_is_flagged_not_hidden():
    rec = lr.label_record("R", "ZipSlip", "exploit", 0, 1, "h", 42, 0, 1, [], {}, 0, False)
    assert rec["victim_found"] is False and rec["pids"] == [] and rec["root_pid"] == -1


def test_refuses_without_ack(tmp_path):
    r = subprocess.run([sys.executable, os.path.join(LAB, "lidds_runner.py"), "--lidds", fake_lidds(tmp_path),
                        "--scenarios", "ZipSlip"], capture_output=True, text=True)
    assert r.returncode == 2 and "--ack-isolated" in r.stderr


def test_list_and_dry_run(tmp_path):
    root = fake_lidds(tmp_path)
    r = subprocess.run([sys.executable, os.path.join(LAB, "lidds_runner.py"), "--lidds", root, "--list"],
                       capture_output=True, text=True)
    assert r.stdout.split() == ["CVE-2014-0160", "ZipSlip"]
    r = subprocess.run([sys.executable, os.path.join(LAB, "lidds_runner.py"), "--lidds", root,
                        "--scenarios", "ZipSlip", "--repeats", "2", "--dry-run"], capture_output=True, text=True)
    assert r.returncode == 0 and "4 executions" in r.stdout and "main.py 1 -1 1" in r.stdout
