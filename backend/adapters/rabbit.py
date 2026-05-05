"""RabbitMQ adapter for message queuing."""
import json
import logging
from typing import Optional
from config import config

logger = logging.getLogger(__name__)

class RabbitAdapter:
    """Publishes to CloudAMQP when RABBITMQ_URL is set."""
    enabled = bool(config.RABBITMQ_URL)
    _conn = None

    @classmethod
    async def _channel(cls):
        if cls._conn is None and cls.enabled:
            try:
                import aio_pika
                cls._conn = await aio_pika.connect_robust(config.RABBITMQ_URL)
            except ImportError:
                logger.warning("aio-pika not installed")
                cls.enabled = False
        return await cls._conn.channel() if cls._conn else None

    @classmethod
    async def enqueue(cls, queue_name: str, payload: dict):
        if cls.enabled:
            try:
                import aio_pika
                ch = await cls._channel()
                await ch.declare_queue(queue_name, durable=True)
                await ch.default_exchange.publish(
                    aio_pika.Message(json.dumps(payload).encode()),
                    routing_key=queue_name,
                )
                logger.info(f"[RABBITMQ->{queue_name}] published")
            except Exception as e:
                logger.error(f"[RABBITMQ-ERR] {e}")
        else:
            logger.info(f"[RABBITMQ-MOCK->{queue_name}] enqueued payload")