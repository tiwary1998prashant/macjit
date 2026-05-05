"""Configuration management for MacJit backend."""
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).parent

def _load_environment_files() -> None:
    load_dotenv(ROOT_DIR / '.env', override=False)
    env_name = os.environ.get('ENVIRONMENT', '') or os.environ.get('APP_ENV', '')
    env_name = str(env_name).strip().lower()
    if env_name in ('prod', 'production'):
        env_name = 'prod'
    if env_name in ('local', 'dev', 'prod', 'test'):
        env_file = ROOT_DIR / f'.env.{env_name}'
        if env_file.exists():
            load_dotenv(env_file, override=True)

_load_environment_files()

class Config:
    """Centralized configuration management."""

    # Database
    MONGO_URL: str = os.environ.get('MONGO_URL', '').strip().strip('"').strip("'")
    DB_NAME: str = os.environ.get('DB_NAME', '').strip().strip('"').strip("'")

    # Security
    JWT_SECRET: str = os.environ.get('JWT_SECRET', 'macjit-dev-secret-change-in-prod')
    JWT_ALG: str = "HS256"
    ENCRYPTION_KEY: str = os.environ.get("ENCRYPTION_KEY", "")

    # External Services
    KAFKA_BOOTSTRAP: Optional[str] = os.environ.get("KAFKA_BOOTSTRAP")
    KAFKA_API_KEY: Optional[str] = os.environ.get("KAFKA_API_KEY")
    KAFKA_API_SECRET: Optional[str] = os.environ.get("KAFKA_API_SECRET")

    RABBITMQ_URL: Optional[str] = os.environ.get("RABBITMQ_URL")

    TWILIO_ACCOUNT_SID: Optional[str] = os.environ.get("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN: Optional[str] = os.environ.get("TWILIO_AUTH_TOKEN")
    TWILIO_WHATSAPP_FROM: str = os.environ.get("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886").strip()
    TWILIO_SMS_FROM: Optional[str] = os.environ.get("TWILIO_SMS_FROM")

    RAZORPAY_KEY_ID: Optional[str] = os.environ.get("RAZORPAY_KEY_ID")
    RAZORPAY_KEY_SECRET: Optional[str] = os.environ.get("RAZORPAY_KEY_SECRET")
    RAZORPAY_WEBHOOK_SECRET: str = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")

    # App Settings
    CORS_ORIGINS: str = os.environ.get('CORS_ORIGINS', '*')
    PUBLIC_URL: str = os.environ.get("PUBLIC_URL") or os.environ.get("APP_URL") or ""

    # Business Logic
    OTP_TTL_SEC: int = 600  # 10 minutes
    SHOP_OPEN_HOUR: int = 8
    SHOP_CLOSE_HOUR: int = 18  # 6 PM

    # Service Durations (minutes)
    SERVICE_DURATIONS = {
        "oil-change": 45,
        "general": 120,
        "ac-service": 90,
        "alignment": 60,
        "brake": 75,
        "engine": 240,
        "full-service": 210,
    }
    DEFAULT_SERVICE_DURATION: int = 120

    # Active booking statuses
    ACTIVE_STATUSES = {"ASSIGNED", "IN_SERVICE"}

    # Customer notification events
    CUSTOMER_NOTIFY_EVENTS = {
        "BOOKING_CREATED", "SERVICE_STARTED", "APPROVAL_REQUESTED",
        "SERVICE_FINISHED", "QA_DONE", "BILLED", "PAID"
    }

    @classmethod
    def get_mongo_url(cls) -> str:
        """Get MongoDB URL with proper protocol."""
        url = cls.MONGO_URL
        if not (url.startswith('mongodb://') or url.startswith('mongodb+srv://')):
            url = 'mongodb+srv://' + url
        return url

# Global config instance
config = Config()