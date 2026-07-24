import asyncio
import os
import yaml
from swarm.orchestrator import RaySwarmOrchestrator

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

    await orchestrator.start_swarm(
        cfg["swarm"],
        grpc_socket=cfg.get("control_plane", {}).get("grpc_socket", "/run/kb/kba.sock"),
    )

if __name__ == "__main__":
    asyncio.run(main())
