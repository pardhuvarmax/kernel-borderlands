# pipeline

`flow.py`: the Ray-free core of the live agent decision path (`kbd StreamEvents -> IngestAgent -> Patroller -> Hunter -> Judge/Jury -> Executor -> kbd`). Event translation, the bounded per-PID coalescer, the incident gate (dedup, cooldown, concurrency cap), the confidence and containment-level policy, and the staged executor. Plain Python so it is unit-tested without Ray (`../tests/test_pipeline_flow.py`); the agents in `../agents/` are thin wrappers. The swarm is advisory: `kbd`'s own enforcement never waits on it.
