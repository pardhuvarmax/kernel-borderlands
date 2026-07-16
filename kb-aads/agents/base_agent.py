import asyncio
import ray
from dataclasses import dataclass
from enum import Enum

class AgentRole(Enum):
    PATROLLER = "patroller"
    HUNTER = "hunter"
    HEALER = "healer"
    CONTAINMENT = "containment"
    JUDGE = "judge"
    JURY = "jury"
    EXECUTOR = "executor"
    IDLE = "idle"

class AgentStatus(Enum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    STOPPED = "stopped"
    ERROR = "error"

@dataclass
class AgentState:
    agent_id: str
    role: AgentRole
    status: AgentStatus = AgentStatus.INITIALIZING
    uptime: int = 0
    anomaly_score: float = 0.0

@ray.remote
class BaseAgent:
    """Ray Actor base class for distributed swarm agents."""
    def __init__(self, agent_id: str, role: AgentRole):
        self.state = AgentState(agent_id=agent_id, role=role)
        self.running = False
        self.message_queue = asyncio.Queue()

    async def start(self):
        self.running = True
        self.state.status = AgentStatus.ACTIVE
        while self.running:
            await self.process_messages()
            await self.tick()
            self.state.uptime += 1
            await asyncio.sleep(1)

    async def stop(self):
        self.running = False
        self.state.status = AgentStatus.STOPPED

    async def tick(self):
        pass

    async def handle_message(self, message: dict):
        pass

    async def receive_message(self, message: dict):
        """Invoked remotely to pass messages across nodes."""
        await self.message_queue.put(message)

    async def process_messages(self):
        while not self.message_queue.empty():
            msg = await self.message_queue.get()
            try:
                await self.handle_message(msg)
            except Exception as e:
                print(f"[{self.state.agent_id}] Message handling failed: {e}")
            self.message_queue.task_done()

    def get_status(self) -> dict:
        return {
            "agent_id": self.state.agent_id,
            "role": self.state.role.value,
            "status": self.state.status.value,
            "uptime": self.state.uptime,
            "anomaly_score": self.state.anomaly_score
        }