# Policy Engine

Runtime behavioral policy evaluation for the KB Control Plane.

## Responsibilities

- Evaluates incoming Process State updates
- Matches behavioral zones against configured policies
- Determines required actions for each process
- Produces enforcement requests
- Supports policy prioritization and overrides
- Exposes deterministic policy decisions

## Policy Sources

- Static configuration
- Runtime operator updates
- Future adaptive policies (AADS)
- Emergency override policies

## Evaluation Inputs

- Process State
- Behavioral Zone
- Composite Score
- EMA Score
- Behavioral Dimensions
- Process Metadata

## Possible Actions

- Allow
- Monitor
- Escalate
- Notify
- Contain
- Kill
- Quarantine
- Delegate to AADS

## Properties

- Deterministic evaluation
- Stateless execution
- Fast lookup
- No AI inference
- Low-latency decision path

## Directory

```
policy.go        // Policy engine
policy_test.go   // Policy evaluation tests
```

The Policy Engine translates behavioral state into security decisions.
It does not execute actions directly; it only decides what should happen.