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
    kbd_keys = {"dim_process", "dim_syscall", "dim_privilege", "dim_file", "dim_network", "dim_memory"}
    assert kbd_keys <= set(schema.NAMES)


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
