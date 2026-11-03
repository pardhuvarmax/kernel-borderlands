"""
Feature contract for learned containment/jury policies. ONE definition used by
training, offline evaluation and the live serving path.

Rules (docs/development/control-aads/learned-policy-retraining.md):
  1. Every feature is a value the sensor/kbd computes at inference time, from
     process telemetry. Nothing derived from an attack label, scenario id or
     target containment level may appear here (FORBIDDEN is enforced).
  2. Names, order, ranges and missing-value rules are fixed per SCHEMA_VERSION.
     Changing any of them requires a new version; checkpoints record the
     version they were trained on and are refused otherwise (gate_checkpoint).
  3. kbd emits the same keys in KBEvent.metadata (feature_schema = "4"; see
     OnProcessState in kb-control-plane/internal/controlplane/controlplane.go).
"""
import json
import os

SCHEMA_VERSION = "4"

# (name, low, high, missing_default). Values are clipped to [low, high].
# Scores are the sensor's 0-100 dimension scores; zone 0/1/2; flags 0/1.
#
# v2 adds dest_class/dest_port (CHANGELOG.md, destination-class wire-contract
# change): derived by kbd from the existing NetFlow (msg_type=9) sample for
# this pid, which already carries destination IP/port — no eBPF/wire change,
# a server-side join (kb-control-plane/internal/controlplane/controlplane.go,
# classifyDestination). dest_class is 0 ("none") until a pid's first observed
# connection. dest_class alone does NOT separate a legitimate backup upload
# from exfiltration at the same kind of address (datasets/attack-lab/
# 20261031T201927: backup_remote and credential_report connect to a loopback
# "backup host", same class as a C2-style address); see
# docs/development/control-aads/learned-policy-retraining.md for what would
# (destination identity/allowlisting, byte volume — the latter needs new
# sensor-side write()/sendto() instrumentation, not yet built).
#
# v3 adds dest_known: 1 when the pid's most recent destination is inside the
# operator's policy.yaml `known_destinations` (a known backup host, internal
# API), else 0 (also 0 when no connection has been seen or nothing is
# configured). It is destination IDENTITY on top of dest_class; it is only as
# good as the operator's list and says nothing about what was sent (bytes_sent
# is still not a feature).
#
# v4 adds tree_dim_file, tree_dim_network and tree_file_net: the highest file
# and network dimension scores across the process's SUBTREE (itself and all
# descendants kbd has seen, incl. recently exited ones; each process counts its
# highest score ever, not its latest), and the lower of the two (high only when
# both kinds of evidence exist in the subtree). Computed in kbd from parent pids
# already on the wire (kb-control-plane/internal/controlplane/tree.go); per-process
# dim_* are unchanged. Limits: walk bounded to 6 levels / 256 nodes; a long-lived
# parent whose descendants collectively read files and connect looks like "both"
# indefinitely; children re-parented to init leave the tree.
FEATURES = [
    ("score",          0.0, 100.0, 0.0),   # kbd EMA score
    ("zone",           0.0,   2.0, 0.0),   # SAFE/SUSPICIOUS/BORDERLANDS
    ("is_root",        0.0,   1.0, 0.0),   # observed euid == 0
    ("score_delta",  -100.0, 100.0, 0.0),  # score minus previous sample for this pid
    ("dim_process",    0.0, 100.0, 0.0),
    ("dim_syscall",    0.0, 100.0, 0.0),
    ("dim_privilege",  0.0, 100.0, 0.0),
    ("dim_file",       0.0, 100.0, 0.0),
    ("dim_network",    0.0, 100.0, 0.0),
    ("dim_memory",     0.0, 100.0, 0.0),
    ("telemetry_gap",  0.0,   1.0, 1.0),   # 1 = this window is known-incomplete OR unknown (fail toward "unsure")
    ("dest_class",     0.0,   5.0, 0.0),   # 0=none 1=loopback 2=private 3=link-local 4=multicast 5=public
    ("dest_port",      0.0, 65535.0, 0.0), # most recent NetFlow dest port for this pid, 0 if none
    ("dest_known",     0.0,   1.0, 0.0),   # 1 = last destination is in policy.yaml known_destinations
    ("tree_dim_file",    0.0, 100.0, 0.0), # max dim_file over the process subtree
    ("tree_dim_network", 0.0, 100.0, 0.0), # max dim_network over the process subtree
    ("tree_file_net",    0.0, 100.0, 0.0), # min of the two: both kinds of evidence somewhere in the subtree
]
NAMES = [f[0] for f in FEATURES]

# Anything that encodes the answer. Training tables carry these as labels
# only; build_vector refuses them as inputs.
FORBIDDEN = {"event_type", "scenario", "scenario_id", "category", "label",
             "target_containment", "target_level", "attack", "is_attack"}

ZONE_IDS = {"SAFE": 0, "SUSPICIOUS": 1, "BORDERLANDS": 2}


def _f(x, default):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def build_vector(raw: dict) -> list:
    """raw: {feature_name: value}. Missing/bad values take the documented
    default; out-of-range values are clipped. Label-like keys are an error."""
    bad = FORBIDDEN & set(raw)
    if bad:
        raise ValueError(f"label-derived inputs are not allowed as features: {sorted(bad)}")
    out = []
    for name, lo, hi, default in FEATURES:
        v = _f(raw.get(name), default)
        out.append(min(max(v, lo), hi))
    return out


def from_event_message(msg: dict, prev_score=None) -> dict:
    """Pipeline message (pipeline.flow.event_to_message) -> raw feature dict."""
    md = msg.get("metadata", {})
    raw = {
        "score": msg.get("score"),
        "zone": msg.get("zone_id"),
        "is_root": 1.0 if msg.get("uid") == 0 else 0.0,
        "score_delta": (msg.get("score", 0.0) - prev_score) if prev_score is not None else 0.0,
        "telemetry_gap": md.get("telemetry_gap", 1.0 if "dim_process" not in md else 0.0),
    }
    for k in ("dim_process", "dim_syscall", "dim_privilege", "dim_file", "dim_network", "dim_memory"):
        raw[k] = md.get(k)
    raw["dest_class"] = md.get("dest_class")
    raw["dest_port"] = md.get("dest_port")
    raw["dest_known"] = md.get("dest_known")
    for k in ("tree_dim_file", "tree_dim_network", "tree_file_net"):
        raw[k] = md.get(k)
    return raw


SCHEMA_FILE = "feature_schema.json"


def schema_descriptor() -> dict:
    return {"version": SCHEMA_VERSION, "features": FEATURES}


def write_schema(checkpoint_dir: str):
    """Training scripts call this next to a new checkpoint."""
    with open(os.path.join(checkpoint_dir, SCHEMA_FILE), "w") as f:
        json.dump(schema_descriptor(), f, indent=1)


def gate_checkpoint(checkpoint_dir: str):
    """(ok, reason). A checkpoint may serve only if it records exactly this
    schema. Legacy checkpoints (trained on the label-derived 5-feature
    observation, no schema file) are refused unless KB_ALLOW_LEGACY_POLICY=1,
    a research-only override that must never be set in production."""
    path = os.path.join(checkpoint_dir, SCHEMA_FILE)
    if not os.path.isfile(path):
        if os.environ.get("KB_ALLOW_LEGACY_POLICY") == "1":
            return True, "legacy checkpoint allowed by KB_ALLOW_LEGACY_POLICY=1 (research only)"
        return False, ("checkpoint has no feature_schema.json: it was trained on the legacy observation "
                       "that includes a label-derived event_type and cannot be served on live data")
    try:
        with open(path) as f:
            d = json.load(f)
    except (OSError, ValueError) as e:
        return False, f"unreadable {SCHEMA_FILE}: {e}"
    if d != json.loads(json.dumps(schema_descriptor())):
        return False, f"checkpoint schema {d.get('version')!r} does not match serving schema {SCHEMA_VERSION!r}"
    return True, "schema matches"
