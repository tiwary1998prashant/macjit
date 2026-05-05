"""Kafka adapter for event publishing."""
import json
import logging
from typing import Optional
from config import config

logger = logging.getLogger(__name__)

class KafkaAdapter:
    """Publishes to Confluent Kafka when KAFKA_BOOTSTRAP/API_KEY/API_SECRET are set."""
    enabled = bool(config.KAFKA_BOOTSTRAP and config.KAFKA_API_KEY)
    _producer = None

    @classmethod
    def _get(cls):
        if cls._producer is None and cls.enabled:
            try:
                from confluent_kafka import Producer
                cls._producer = Producer({
                    "bootstrap.servers": config.KAFKA_BOOTSTRAP,
                    "security.protocol": "SASL_SSL",
                    "sasl.mechanisms": "PLAIN",
                    "sasl.username": config.KAFKA_API_KEY,
                    "sasl.password": config.KAFKA_API_SECRET,
                })
            except ImportError:
                logger.warning("confluent-kafka not installed")
                cls.enabled = False
        return cls._producer

    @classmethod
    async def publish(cls, topic: str, event: dict):
        if cls.enabled:
            try:
                p = cls._get()
                p.produce(topic, json.dumps(event).encode())
                p.poll(0)
                logger.info(f"[KAFKA->{topic}] {event['type']}")
            except Exception as e:
                logger.error(f"[KAFKA-ERR] {e}")
        else:
            logger.info(f"[KAFKA-MOCK->{topic}] {event['type']} | id={event.get('booking_id','')}")