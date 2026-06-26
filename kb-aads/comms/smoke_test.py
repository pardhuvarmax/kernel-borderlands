"""
1) docker compose -f docker-compose.kafka.yml up -d
2) python -m comms.smoke_test
"""
import asyncio
from comms.kafka_bus import KafkaBus
from comms.zmq_channel import AgentBroker, AgentLink
from comms.messages import HealthCheck, DirectMessage


async def main():
    # --- ZeroMQ direct channel ---
    broker = AgentBroker()
    await broker.start()

    hunter_link = AgentLink("hunter-test")
    containment_link = AgentLink("containment-test")

    received: list[DirectMessage] = []

    async def on_direct(msg: DirectMessage):
        received.append(msg)
        print(f"[containment-test] got: {msg.intent} {msg.body}")

    await containment_link.listen(on_direct)
    await asyncio.sleep(0.2)

    await hunter_link.send_to("containment-test", "contain_pid", {"pid": 4242, "score": 91.0})
    await asyncio.sleep(0.3)
    assert received and received[0].intent == "contain_pid", "ZeroMQ direct message failed"
    print("ZeroMQ direct channel OK")

    # --- Kafka event bus ---
    bus = KafkaBus(agent_id="smoke-test")
    await bus.start()
    seen = asyncio.Event()

    async def on_health(msg: HealthCheck):
        print(f"[smoke-test] got health check from {msg.sender}")
        seen.set()

    await bus.subscribe(["health-checks"], on_health)
    await asyncio.sleep(1.0)  # let the consumer group join
    await bus.publish_health(HealthCheck(sender="hunter-1", agent_id="hunter-1", healthy=True, latency_ms=3.2))

    try:
        await asyncio.wait_for(seen.wait(), timeout=10)
        print("Kafka event bus OK")
    except asyncio.TimeoutError:
        print("Kafka round-trip timed out — check the broker is up")

    await bus.stop()
    await containment_link.close()
    await broker.stop()


if __name__ == "__main__":
    asyncio.run(main())