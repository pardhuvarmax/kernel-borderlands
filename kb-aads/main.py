import asyncio
from swarm.orchestrator import SwarmOrchestrator

async def main():
    print("╔══════════════════════════════════════════╗")
    print("║   KB AADS — Agent Swarm v0.1             ║")
    print("║   Kernel Borderlands                     ║")
    print("╚══════════════════════════════════════════╝")

    orchestrator = SwarmOrchestrator()

    config = {
        "patrollers": 2,
        "hunters": 2,
        "healers": 1,
        "containment": 1
    }

    await orchestrator.start_swarm(config)

if __name__ == "__main__":
    asyncio.run(main())