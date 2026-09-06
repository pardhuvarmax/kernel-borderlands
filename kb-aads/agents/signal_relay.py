import itertools

import ray

from .base_agent import BaseAgent, AgentRole


@ray.remote
class SignalRelayAgent(BaseAgent):
    """
    Dedicated messenger agent: routes a message to a named destination pool.

    Per the roadmap's framing (docs/development/control-aads/aads-
    intelligence-roadmap.md, line 63): "highly active... closer to
    Patroller in shape... than to a one-shot function call" — a real
    long-lived actor sitting on the hot path, not a passive library call.
    No model, ever, and none should be added — a relay is pure dispatch
    infrastructure; judgment belongs to the agents on either end of it,
    not the wire between them.

    routes: dict[str, list[ActorHandle]] — named pools this relay knows
    how to reach (e.g. {"hunter": hunter_pool}), round-robinned per route
    name the same way PatrollerAgent round-robins its hunter_pool.

    Scoping note (mirrors marl/README.md's honest-gap convention): the
    roadmap explicitly leaves "which agent-pairs route through a relay vs.
    call each other directly" as unresolved before Phase 4. This class is
    a real, functional, tested router — but no existing agent (Patroller,
    Hunter, Judge) has been rewired to send through it instead of calling
    peers directly yet. That rewiring is a separate, deliberate integration
    decision for whoever picks up Phase 4, not made here.
    """

    def __init__(self, agent_id: str, routes: dict = None):
        super().__init__(agent_id, AgentRole.SIGNAL_RELAY)
        self.routes = {name: list(pool) for name, pool in (routes or {}).items()}
        self._cycles = {name: itertools.cycle(pool) for name, pool in self.routes.items() if pool}
        self._relayed_count = 0

    async def tick(self):
        self.state.last_action = f"Relaying across {len(self.routes)} route(s), {self._relayed_count} dispatched so far"

    async def handle_message(self, message: dict):
        if message.get("type") != "RELAY":
            return
        route = message.get("route")
        payload = message.get("payload", {})

        cycle = self._cycles.get(route)
        if cycle is None:
            print(f"[{self.state.agent_id}] no destinations for route {route!r} — dropped")
            return

        target = next(cycle)
        await target.receive_message.remote(payload)
        self._relayed_count += 1
        self.state.last_action = f"Relayed to route {route!r} ({self._relayed_count} total)"
