"""
Pydantic schemas for every AADS message, plus protobuf wire encoding.

FR-505 requires Kafka messages to be valid Protobuf, not raw JSON/text.
Rather than hand-writing a .proto per message type before the schemas have
settled, we encode each Pydantic model into a google.protobuf.Struct before
publishing — that's genuine protobuf bytes on the wire today. Swap in
generated *_pb2 classes later without touching any agent-facing code below.

Note: Struct stores all numbers as double, so int fields round-trip through
float64 (fine for PIDs/scores, just don't rely on it for huge integers).
"""
from __future__ import annotations

import time
from typing import Any, Literal
from pydantic import BaseModel, Field
from google.protobuf.struct_pb2 import Struct
from google.protobuf.json_format import MessageToDict, ParseDict


class Envelope(BaseModel):
    sender: str
    ts: float = Field(default_factory=time.time)


class RoleChange(Envelope):
    msg_type: Literal["role_change"] = "role_change"
    agent_id: str
    old_role: str
    new_role: str
    reason: str | None = None


class AgentUpdate(Envelope):
    msg_type: Literal["agent_update"] = "agent_update"
    agent_id: str
    status: str
    last_action: str
    uptime: int


class ConsensusEvent(Envelope):
    msg_type: Literal["consensus_event"] = "consensus_event"
    proposal_id: str
    topic: str
    votes: dict[str, bool]
    outcome: Literal["pending", "approved", "rejected"]


class HealthCheck(Envelope):
    msg_type: Literal["health_check"] = "health_check"
    agent_id: str
    healthy: bool
    latency_ms: float


class AnomalyAlert(Envelope):
    msg_type: Literal["anomaly_alert"] = "anomaly_alert"
    pid: int
    score: float
    zone: Literal["safe", "suspicious", "borderlands"]
    confidence: float = 0.0
    evidence: dict[str, Any] = Field(default_factory=dict)


class DirectMessage(Envelope):
    """Point-to-point payload carried over ZeroMQ (not Kafka)."""
    msg_type: Literal["direct"] = "direct"
    recipient: str
    intent: str  # e.g. "contain_pid", "heal_request", "ping"
    body: dict[str, Any] = Field(default_factory=dict)


TOPIC_SCHEMAS: dict[str, type[Envelope]] = {
    "role-changes": RoleChange,
    "agent-updates": AgentUpdate,
    "consensus-events": ConsensusEvent,
    "health-checks": HealthCheck,
    "anomaly-alerts": AnomalyAlert,
}


def encode(message: Envelope) -> bytes:
    struct = Struct()
    ParseDict(message.model_dump(mode="json"), struct)
    return struct.SerializeToString()


def decode(data: bytes, schema: type[Envelope]) -> Envelope:
    struct = Struct()
    struct.ParseFromString(data)
    return schema.model_validate(MessageToDict(struct))