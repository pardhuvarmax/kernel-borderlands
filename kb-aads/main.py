import asyncio
import os
import yaml
from swarm.orchestrator import RaySwarmOrchestrator
from api.status_server import start_status_server

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "agents.yaml")


def load_config(path: str = CONFIG_PATH) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


async def main():
    print("╔══════════════════════════════════════════╗")
    print("║   KB AADS — Agent Swarm v0.1             ║")
    print("║   Kernel Borderlands                     ║")
    print("╚══════════════════════════════════════════╝")

    cfg = load_config()
    orchestrator = RaySwarmOrchestrator(ray_mode=cfg.get("ray", {}).get("mode", "local"))

    # Started before start_swarm (which blocks forever driving agent tick
    # loops) — see api/status_server.py for why this exists. Address/port
    # overridable via env so a dev box running multiple swarms doesn't
    # collide; kbd's proxy handler (KB_AADS_API_ADDR) must point at the
    # same address.
    status_addr = os.environ.get("KB_AADS_STATUS_HOST", "127.0.0.1")
    status_port = int(os.environ.get("KB_AADS_STATUS_PORT", "8601"))
    start_status_server(orchestrator.registry, addr=status_addr, port=status_port)
    print(f"[AADS] Agent status server listening on {status_addr}:{status_port}")

    await orchestrator.start_swarm(
        cfg["swarm"],
        grpc_socket=cfg.get("control_plane", {}).get("grpc_socket", "/run/kb/kba.sock"),
        jury_pool_size=cfg.get("jury", {}).get("pool_size", 5),
        patroller_suspicious_threshold=cfg.get("patroller", {}).get("suspicious_threshold", 40.0),
    )

if __name__ == "__main__":
    asyncio.run(main())
