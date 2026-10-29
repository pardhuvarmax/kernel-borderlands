"""
Event capture for the attack lab: records kbd's StreamEvents feed (the same
feed the live swarm consumes, feature schema v1) to JSONL, stamped with the
wall-clock time each event was RECEIVED (recv_ns).

recv_ns, not the sensor's own timestamp, is what labeling uses to window events
against execution start/end, because the sensor clock is not wall time.

The stream can drop out (kbd restart) or be overrun (kbd's per-subscriber
channel is bounded and drops when full). Disconnects are recorded as
{"gap": ...} marker lines so a window with missing telemetry is detectable
later (telemetry_gap), never silently treated as "nothing happened".

Needs grpc + the kb-aads proto stubs (run with the kb-aads venv).
"""
import json
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AADS = os.path.abspath(os.path.join(HERE, "..", "..", "kb-aads"))
for p in (AADS, os.path.join(AADS, "comms")):
    if p not in sys.path:
        sys.path.insert(0, p)


class Capture:
    def __init__(self, out_path, socket_path="/run/kb/kba.sock", client_factory=None):
        self.out_path = out_path
        self.socket_path = socket_path
        self._factory = client_factory
        self._stop = threading.Event()
        self._thread = None
        self.count = 0
        self.gaps = 0
        self.connected = threading.Event()

    def _client(self):
        if self._factory:
            return self._factory()
        from comms.grpc_client import ControlPlaneClient  # lazy: tests run without grpc
        return ControlPlaneClient(socket_path=self.socket_path)

    @staticmethod
    def _wait_ready(client, timeout=3.0):
        """Raise unless the channel really connects (e.g. no permission on the
        socket, kbd down). Clients without a gRPC channel (test fakes) pass."""
        ch = getattr(client, "channel", None)
        if ch is None:
            return
        import grpc
        grpc.channel_ready_future(ch).result(timeout=timeout)

    def _run(self):
        with open(self.out_path, "a", buffering=1) as out:
            backoff = 0.5
            while not self._stop.is_set():
                client = None
                try:
                    client = self._client()
                    self._wait_ready(client)  # gRPC connects lazily: prove the socket is usable
                    stream = client.stream_events(["process_state", "zone_transition"])
                    self.connected.set()
                    backoff = 0.5
                    for ev in stream:
                        out.write(json.dumps({
                            "recv_ns": time.time_ns(), "pid": ev.pid, "ppid": ev.ppid,
                            "comm": ev.comm, "event_type": ev.event_type,
                            "score_delta": ev.score_delta, "ts": ev.timestamp,
                            "metadata": dict(ev.metadata)}) + "\n")
                        self.count += 1
                        if self._stop.is_set():
                            break
                except Exception as e:  # noqa: BLE001 - record and retry, never die silently
                    if not self._stop.is_set():
                        self.gaps += 1
                        out.write(json.dumps({"gap": True, "recv_ns": time.time_ns(),
                                              "error": type(e).__name__}) + "\n")
                finally:
                    if client is not None:
                        try:
                            client.close()
                        except Exception:  # noqa: BLE001
                            pass
                if not self._stop.is_set():
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 10.0)

    def start(self, wait_s=10.0):
        self._thread = threading.Thread(target=self._run, daemon=True, name="lab-capture")
        self._thread.start()
        if not self.connected.wait(wait_s):
            self.stop()
            raise RuntimeError(
                f"capture could not connect to kbd at {self.socket_path} within {wait_s}s. "
                "Is kbd running, and is this user in the `kb` group? "
                "(without changing groups: sudo -u $USER -g kb python3 runner.py ...)")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
