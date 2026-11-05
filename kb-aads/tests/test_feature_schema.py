import json, os, sys, tempfile
import pytest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from features import schema


def test_label_derived_inputs_are_refused():
    for k in ("event_type", "scenario", "target_level", "label"):
        with pytest.raises(ValueError):
            schema.build_vector({"score": 50, k: 3})


def test_vector_is_ordered_clipped_and_defaults_missing():
    v = schema.build_vector({"score": 250, "zone": 2, "dim_memory": "bad"})
    assert len(v) == len(schema.NAMES)
    assert v[0] == 100.0 and v[1] == 2.0 and v[schema.NAMES.index("dim_memory")] == 0.0
    assert v[schema.NAMES.index("telemetry_gap")] == 1.0  # unknown telemetry => flagged incomplete


def test_serving_features_match_what_kbd_emits():
    # keys kbd puts in KBEvent.metadata (controlplane.go OnProcessState)
    kbd_keys = {"dim_process", "dim_syscall", "dim_privilege", "dim_file", "dim_network", "dim_memory",
                "dest_class", "dest_port", "dest_known",
                "tree_dim_file", "tree_dim_network", "tree_file_net",
                "sensitive_file_count", "cred_change_count", "dropped_events",
                "seq_cred_then_connect", "seq_shell_then_connect", "seq_connect_then_memexec",
                "bytes_sent_kib"}
    assert kbd_keys <= set(schema.NAMES)


def test_dest_class_defaults_to_none_and_from_event_message_reads_it():
    v = schema.build_vector({"score": 50})
    assert v[schema.NAMES.index("dest_class")] == 0.0
    assert v[schema.NAMES.index("dest_port")] == 0.0
    msg = {"metadata": {"dim_process": "1", "dest_class": "2", "dest_port": "4444"}}
    raw = schema.from_event_message(msg)
    assert raw["dest_class"] == "2" and raw["dest_port"] == "4444"
    v = schema.build_vector(raw)
    assert v[schema.NAMES.index("dest_class")] == 2.0
    assert v[schema.NAMES.index("dest_port")] == 4444.0


def test_gate_refuses_legacy_and_mismatch_accepts_current(monkeypatch):
    monkeypatch.delenv("KB_ALLOW_LEGACY_POLICY", raising=False)
    d = tempfile.mkdtemp()
    assert schema.gate_checkpoint(d)[0] is False                    # legacy: no schema file
    monkeypatch.setenv("KB_ALLOW_LEGACY_POLICY", "1")
    assert schema.gate_checkpoint(d)[0] is True                     # explicit research override
    monkeypatch.delenv("KB_ALLOW_LEGACY_POLICY")
    schema.write_schema(d)
    assert schema.gate_checkpoint(d)[0] is True
    json.dump({"version": "0", "features": []}, open(os.path.join(d, schema.SCHEMA_FILE), "w"))
    assert schema.gate_checkpoint(d)[0] is False


def test_shipped_checkpoints_are_refused_without_override(monkeypatch):
    monkeypatch.delenv("KB_ALLOW_LEGACY_POLICY", raising=False)
    root = os.path.join(os.path.dirname(__file__), "..", "marl", "checkpoints")
    for name in ("containment_ppo", "jury_ppo"):
        assert schema.gate_checkpoint(os.path.join(root, name))[0] is False


def test_dest_known_defaults_to_zero_and_is_read_from_event_message():
    assert schema.build_vector({"score": 50})[schema.NAMES.index("dest_known")] == 0.0
    raw = schema.from_event_message({"metadata": {"dim_process": "1", "dest_known": "1"}})
    assert schema.build_vector(raw)[schema.NAMES.index("dest_known")] == 1.0
    raw = schema.from_event_message({"metadata": {"dim_process": "1", "dest_known": "7"}})
    assert schema.build_vector(raw)[schema.NAMES.index("dest_known")] == 1.0  # clipped


def test_tree_features_default_to_zero_and_are_read_and_clipped():
    v = schema.build_vector({"score": 50})
    for k in ("tree_dim_file", "tree_dim_network", "tree_file_net"):
        assert v[schema.NAMES.index(k)] == 0.0
    msg = {"metadata": {"dim_process": "1", "tree_dim_file": "80.00", "tree_dim_network": "70.00",
                        "tree_file_net": "700"}}
    v = schema.build_vector(schema.from_event_message(msg))
    assert v[schema.NAMES.index("tree_dim_file")] == 80.0
    assert v[schema.NAMES.index("tree_dim_network")] == 70.0
    assert v[schema.NAMES.index("tree_file_net")] == 100.0  # clipped


def test_counter_features_default_to_zero_and_are_read_and_clipped():
    names = ["sensitive_file_count", "cred_change_count", "dropped_events",
             "seq_cred_then_connect", "seq_shell_then_connect", "seq_connect_then_memexec"]
    v = schema.build_vector({"score": 50})
    assert all(v[schema.NAMES.index(k)] == 0.0 for k in names)
    md = {"dim_process": "1", "sensitive_file_count": "3", "cred_change_count": "99999",
          "dropped_events": "9", "seq_cred_then_connect": "1", "seq_connect_then_memexec": "1",
          "telemetry_gap": "1"}
    raw = schema.from_event_message({"metadata": md})
    v = schema.build_vector(raw)
    assert v[schema.NAMES.index("sensitive_file_count")] == 3.0
    assert v[schema.NAMES.index("cred_change_count")] == 10000.0      # clipped
    assert v[schema.NAMES.index("seq_shell_then_connect")] == 0.0
    assert v[schema.NAMES.index("seq_connect_then_memexec")] == 1.0
    assert v[schema.NAMES.index("telemetry_gap")] == 1.0              # measured gap reaches the vector


def test_bytes_sent_kib_defaults_to_zero_is_read_and_clipped():
    assert schema.build_vector({"score": 50})[schema.NAMES.index("bytes_sent_kib")] == 0.0
    raw = schema.from_event_message({"metadata": {"dim_process": "1", "bytes_sent_kib": "5120"}})
    assert schema.build_vector(raw)[schema.NAMES.index("bytes_sent_kib")] == 5120.0
    raw = schema.from_event_message({"metadata": {"dim_process": "1", "bytes_sent_kib": "99999999999"}})
    assert schema.build_vector(raw)[schema.NAMES.index("bytes_sent_kib")] == 10000000.0
