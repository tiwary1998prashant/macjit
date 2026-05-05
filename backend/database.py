"""Database connection and utilities."""
import logging
from motor.motor_asyncio import AsyncIOMotorClient
from config import config

logger = logging.getLogger(__name__)

# Database connection
client = AsyncIOMotorClient(config.get_mongo_url())
db = client[config.DB_NAME]

async def ping_db() -> bool:
    """Test database connection."""
    try:
        await client.admin.command('ping')
        return True
    except Exception as e:
        logger.error(f"Database ping failed: {e}")
        return False

async def close_db():
    """Close database connection."""
    client.close()
    logger.info("Database connection closed")