"""
Async Kafka event bus for AADS. Wraps aiokafka so agents publish/consume
typed Pydantic messages without touching producer/consumer plumbing.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from .messages import Envelope, TOPIC_SCHEMAS, encode, decode
from .topics import Topics

log = logging.getLogger("kb.aads.kafka")

Handler = Callable[[Envelope], Awaitable[None]]


class KafkaBus:
    def __init__(self, agent_id: str, bootstrap_servers: str = "localhost:9092"):
        self.agent_id = agent_id
        self.bootstrap_servers = bootstrap_servers
        self._producer: AIOKafkaProducer | None = None
        self._consumer_tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        self._producer = AIOKafkaProducer(bootstrap_servers=self.bootstrap_servers)
        await self._producer.start()
        log.info(f"[{self.agent_id}] KafkaBus connected ({self.bootstrap_servers})")

    async def stop(self) -> None:
        for task in self._consumer_tasks:
            task.cancel()
        if self._producer:
            await self._producer.stop()
        log.info(f"[{self.agent_id}] KafkaBus stopped")

    async def publish(self, topic: str, message: Envelope) -> None:
        if not self._producer:
            raise RuntimeError("call KafkaBus.start() before publish()")
        await self._producer.send_and_wait(topic, encode(message))

    async def subscribe(self, topics: list[str], handler: Handler, group: str | None = None) -> None:
        """Spawn a background consumer loop for one or more topics."""
        consumer = AIOKafkaConsumer(
            *topics,
            bootstrap_servers=self.bootstrap_servers,
            group_id=group or f"aads-{self.agent_id}",
            auto_offset_reset="latest",
        )
        await consumer.start()

        async def _loop():
            try:
                async for record in consumer:
                    schema = TOPIC_SCHEMAS.get(record.topic)
                    if not schema:
                        continue
                    try:
                        message = decode(record.value, schema)
                    except Exception:
                        log.exception(f"[{self.agent_id}] bad message on {record.topic}")
                        continue
                    await handler(message)
            finally:
                await consumer.stop()

        self._consumer_tasks.append(asyncio.create_task(_loop()))

    # Convenience wrappers for the five well-known topics
    async def publish_alert(self, alert) -> None:
        await self.publish(Topics.ANOMALY_ALERTS, alert)

    async def publish_health(self, health) -> None:
        await self.publish(Topics.HEALTH_CHECKS, health)

    async def publish_update(self, update) -> None:
        await self.publish(Topics.AGENT_UPDATES, update)