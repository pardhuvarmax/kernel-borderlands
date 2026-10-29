import asyncio
import threading
import time

import ray

from .base_agent import BaseAgent, AgentRole, AgentStatus
from comms.grpc_client import ControlPlaneClient
from pipeline.flow import Coalescer, event_to_message


@ray.remote
class IngestAgent(BaseAgent):
    """
    The live feed: kbd StreamEvents -> bounded coalescing buffer -> Patrollers.

    Closes the gap documented in docs/development/control-aads/
    kb-events-swarm-ingestion-gap.md. Own ControlPlaneClient (a streaming
    instance can never share a channel with a unary one).

    Flood behaviour: the gRPC reader thread only translates and put()s into
    a bounded Coalescer (latest-wins per PID, lowest-score shed first, every
    merge/drop counted), so a producer burst can never grow memory or block
    the reader. A separate drain loop dispatches at a capped rate with a cap
    on un-awaited Patroller sends. If kbd is down the reader reconnects with
    exponential backoff (no log spam: one line per state change). The swarm
    is advisory; kbd's own enforcement never waits on this agent.
    """

    def __init__(self, agent_id: str, patrollers=None, socket_path: str = "/run/kb/kba.sock",
                 capacity: int = 1024, batch: int = 64, interval_s: float = 0.05,
                 max_pending_sends: int = 256, client_factory=None):
        super().__init__(agent_id, AgentRole.INGEST)
        self.patrollers = list(patrollers or [])
        self._socket_path = socket_path
        self._client_factory = client_factory or (lambda: ControlPlaneClient(socket_path=socket_path))
        self.buf = Coalescer(capacity)
        self._lock = threading.Lock()
        self.batch, self.interval_s, self.max_pending_sends = batch, interval_s, max_pending_sends
        self._pending = []
        self.dispatched = 0
        self.send_shed = 0
        self.stream_state = "disconnected"
        self.reconnects = 0
        self._reader = None

    def _read_loop(self):
        backoff = 0.5
        while self.running:
            client = None
            try:
                client = self._client_factory()
                stream = client.stream_events(["process_state", "zone_transition"])
                if self.stream_state != "streaming":
                    print(f"[{self.state.agent_id}] event stream up", flush=True)
                self.stream_state, backoff = "streaming", 0.5
                for ev in stream:
                    msg = event_to_message(ev)
                    if msg is not None:
                        with self._lock:
                            self.buf.put(msg)
                    if not self.running:
                        break
            except Exception as e:  # noqa: BLE001
                if self.stream_state != "disconnected":
                    print(f"[{self.state.agent_id}] event stream lost ({type(e).__name__}); retrying", flush=True)
                self.stream_state = "disconnected"
            finally:
                if client is not None:
                    try:
                        client.close()
                    except Exception:  # noqa: BLE001
                        pass
            self.reconnects += 1
            time.sleep(backoff)
            backoff = min(backoff * 2, 15.0)

    async def start(self):
        self.running = True
        self.state.status = AgentStatus.ACTIVE
        self._reader = threading.Thread(target=self._read_loop, daemon=True, name="kb-ingest-reader")
        self._reader.start()
        while self.running:
            await self.drain_once()
            self.state.uptime += 1
            await asyncio.sleep(self.interval_s)

    async def drain_once(self) -> int:
        """Dispatch up to `batch` coalesced events; PID-sticky Patroller choice."""
        self._pending = [f for f in self._pending if not self._done(f)]
        if not self.patrollers:
            return 0
        with self._lock:
            msgs = self.buf.drain(self.batch)
        n = 0
        for m in msgs:
            if len(self._pending) >= self.max_pending_sends:
                self.send_shed += 1  # Patrollers are behind: shed, counted
                continue
            self._pending.append(self.patrollers[m["pid"] % len(self.patrollers)].receive_message.remote(m))
            n += 1
        self.dispatched += n
        self.state.last_action = f"stream={self.stream_state} dispatched={self.dispatched} pending={len(self.buf)}"
        return n

    @staticmethod
    def _done(ref) -> bool:
        ready, _ = ray.wait([ref], timeout=0)
        return bool(ready)

    def get_ingest_stats(self) -> dict:
        with self._lock:
            b = self.buf.stats()
        return dict(b, dispatched=self.dispatched, send_shed=self.send_shed,
                    stream=self.stream_state, reconnects=self.reconnects)

    async def stop(self):
        await super().stop()
