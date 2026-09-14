"""
Minimal read-only HTTP status server for the AADS swarm, started on a
background thread from main.py. Exists so kb-op/kb-dashboard's Rogue
Management page (via kbd's /api/agents proxy — see
kb-control-plane/internal/controlplane/http.go's handleAgents) has
something real to read, instead of the static placeholder text it shipped
with. No prior mechanism let any HTTP client see Ray-side agent state —
kb-aads only ever dials OUT to kbd over gRPC (comms/grpc_client.py); there
was no path in the other direction.

Deliberately does NOT call JudgeAgent.assess_severity for each agent on
every request: that method's liveness check does `asyncio.sleep(...)` per
agent (consensus/jje.py), so calling it here would make every dashboard
page load block for N * liveness_check_seconds. This exposes each agent's
raw registry status (role/status/uptime/error_count) instead — real
backend state, just not the enforcement-tier health computation itself.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import ray


class _AgentStatusHandler(BaseHTTPRequestHandler):
    registry = None  # bound per-instance by start_status_server, see below

    def do_GET(self):
        if self.path != "/agents":
            self.send_response(404)
            self.end_headers()
            return
        try:
            entries = ray.get(self.registry.list_all.remote())
            agents = []
            for agent_id, meta in entries.items():
                handle = ray.get(self.registry.get_handle.remote(agent_id))
                status = ray.get(handle.get_status.remote()) if handle is not None else {}
                agents.append({
                    "agent_id": agent_id,
                    "role": meta.get("role"),
                    "registry_status": meta.get("status"),
                    "uptime": status.get("uptime"),
                    "error_count": status.get("error_count"),
                    "last_action": status.get("last_action"),
                })
            body = json.dumps({"agents": agents}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:  # status endpoint must never crash the swarm
            body = json.dumps({"error": str(exc)}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format, *args):  # silence default stderr access log
        pass


def start_status_server(registry, addr: str = "127.0.0.1", port: int = 8601) -> HTTPServer:
    """Starts the status server on a background daemon thread. Returns the
    HTTPServer instance — the caller doesn't need to hold onto it for the
    server to keep running (the thread is a daemon), but may call
    .shutdown() in tests."""
    handler_cls = type("_BoundAgentStatusHandler", (_AgentStatusHandler,), {"registry": registry})
    server = HTTPServer((addr, port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
