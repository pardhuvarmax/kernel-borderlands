"""Kafka topic names for AADS inter-agent communication."""

class Topics:
    ROLE_CHANGES = "role-changes"
    AGENT_UPDATES = "agent-updates"
    CONSENSUS_EVENTS = "consensus-events"
    HEALTH_CHECKS = "health-checks"
    ANOMALY_ALERTS = "anomaly-alerts"

    ALL = (ROLE_CHANGES, AGENT_UPDATES, CONSENSUS_EVENTS, HEALTH_CHECKS, ANOMALY_ALERTS)