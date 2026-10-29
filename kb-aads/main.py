import argparse
import asyncio
import os
import yaml
from swarm.orchestrator import RaySwarmOrchestrator
from api.status_server import start_status_server

# Relative-path default, unchanged for dev runs (`python3 main.py` from
# inside kb-aads/, config/ a sibling of the repo root) — but this breaks
# once kb-aads is installed anywhere else (e.g. /usr/local/share/kb-aads,
# where "../config/agents.yaml" resolves to a path that doesn't exist).
# --config (below) is the real fix for that, matching the /etc/kb/
# convention kbd's --policy/--rules/--workloads already use; the
# packaging/bin/kbagents wrapper script passes --config /etc/kb/agents.yaml.
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "agents.yaml")


def load_config(path: str = CONFIG_PATH) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


async def main():
    parser = argparse.ArgumentParser(description="kbagents — Kernel Borderlands Agent Swarm (kb-aads)")
    parser.add_argument("--config", default=CONFIG_PATH, help="path to agents.yaml (default: %(default)s)")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════╗")
    print("║   KB AADS — Agent Swarm v0.1             ║")
    print("║   Kernel Borderlands                     ║")
    print("╚══════════════════════════════════════════╝")

    cfg = load_config(args.config)
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
        use_learned_policy=cfg.get("policy", {}).get("use_learned", False),
    )

if __name__ == "__main__":
    asyncio.run(main())
