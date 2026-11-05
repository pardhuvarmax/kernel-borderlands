import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
import batch  # noqa: E402


def test_known_destinations_is_added_when_absent_and_leaves_the_rest_alone():
    src = "defaults:\n  suspicious: 40.0\npolicies:\n  - comm: nginx\n    suspicious: 55.0\n"
    out = batch.with_known_destinations(src, ["127.0.0.3", "127.0.0.5"])
    assert out.startswith(src)
    assert out.endswith("known_destinations: [127.0.0.3, 127.0.0.5]\n")


def test_known_destinations_replaces_an_existing_key_with_its_continuation_lines():
    src = ("sensitive_paths: []\n\n"
           "# comment above\nknown_destinations: []\n  # - 10.20.0.5\n  # - 192.168.50.0/24\n\n"
           "policies:\n  - comm: nginx\n")
    out = batch.with_known_destinations(src, ["127.0.0.3"])
    assert out.count("known_destinations") == 1
    assert "# - 10.20.0.5" not in out and "policies:\n  - comm: nginx" in out and "sensitive_paths: []" in out
    assert out.endswith("known_destinations: [127.0.0.3]\n")


def test_known_destinations_is_idempotent():
    src = "defaults:\n  suspicious: 40.0\n"
    once = batch.with_known_destinations(src, ["127.0.0.3"])
    assert batch.with_known_destinations(once, ["127.0.0.3"]) == once


def test_time_box_only_starts_seeds_that_can_finish():
    per = batch.estimate_seed_minutes(["benign_idle", "credential_access"], repeats=1)
    assert per > 0
    assert batch.seeds_that_fit([1, 2, 3, 4], per_seed_min=20, max_minutes=55) == [1, 2]
    assert batch.seeds_that_fit([1], per_seed_min=70, max_minutes=55) == []


def test_dry_run_changes_nothing_and_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["batch.py", "--dry-run", "--seeds", "2,3", "--out", "/nonexistent"])
    assert batch.main() == 0
    assert "will run" in capsys.readouterr().out
