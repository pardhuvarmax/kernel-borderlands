"""
Low-latency direct agent-to-agent messaging over ZeroMQ.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

import zmq
import zmq.asyncio

from .messages import DirectMessage, encode, decode

log = logging.getLogger("kb.aads.zmq")

DirectHandler = Callable[[DirectMessage], Awaitable[None]]


class AgentBroker:
    """ROUTER socket that relays DirectMessages between connected agents."""

    def __init__(self, bind_addr: str = "tcp://127.0.0.1:5555"):
        self.bind_addr = bind_addr
        self._ctx = zmq.asyncio.Context.instance()
        self._router = self._ctx.socket(zmq.ROUTER)
        self._identities: dict[str, bytes] = {}
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._router.bind(self.bind_addr)
        self._task = asyncio.create_task(self._loop())
        log.info(f"[Broker] listening on {self.bind_addr}")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._router.close()

    async def _loop(self):
        while True:
            identity, _, payload = await self._router.recv_multipart()

            try:
                msg = decode(payload, DirectMessage)
            except Exception:
                log.exception("[Broker] dropped malformed frame")
                continue

            # Learn sender identity
            self._identities[msg.sender] = identity

            # Registration packet
            if msg.intent == "__register__":
                log.info(f"[Broker] registered {msg.sender}")
                continue

            target = self._identities.get(msg.recipient)

            if target is None:
                log.warning(
                    f"[Broker] unknown recipient '{msg.recipient}', dropping ({msg.intent})"
                )
                continue

            await self._router.send_multipart(
                [target, b"", payload]
            )


class AgentLink:
    """DEALER socket owned by one agent."""

    def __init__(
        self,
        agent_id: str,
        connect_addr: str = "tcp://127.0.0.1:5555",
    ):
        self.agent_id = agent_id
        self._ctx = zmq.asyncio.Context.instance()
        self._dealer = self._ctx.socket(zmq.DEALER)
        self._dealer.setsockopt_string(zmq.IDENTITY, agent_id)
        self._dealer.connect(connect_addr)

        self._task: asyncio.Task | None = None

    async def _register(self):
        msg = DirectMessage(
            sender=self.agent_id,
            recipient="broker",
            intent="__register__",
            body={}
        )

        await self._dealer.send_multipart(
            [b"", encode(msg)]
        )

    async def send_to(
        self,
        recipient: str,
        intent: str,
        body: dict | None = None,
    ) -> None:

        msg = DirectMessage(
            sender=self.agent_id,
            recipient=recipient,
            intent=intent,
            body=body or {},
        )

        await self._dealer.send_multipart(
            [b"", encode(msg)]
        )

    async def listen(self, handler: DirectHandler) -> None:
        # Register immediately so broker knows about us
        await self._register()

        async def _loop():
            while True:
                _, payload = await self._dealer.recv_multipart()

                try:
                    msg = decode(payload, DirectMessage)
                except Exception:
                    log.exception(
                        f"[{self.agent_id}] dropped malformed direct message"
                    )
                    continue

                await handler(msg)

        self._task = asyncio.create_task(_loop())

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        self._dealer.close()