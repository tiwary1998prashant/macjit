"""OTP (One-Time Password) utilities."""
import hmac
import random
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict
from config import config

logger = logging.getLogger(__name__)

# In-memory OTP store (in production, use Redis or database)
_approval_otps: Dict[str, dict] = {}

def generate_otp() -> str:
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))

def store_otp(booking_id: str, otp: str, phone: str):
    """Store OTP for booking approval."""
    if not phone:
        raise ValueError("Phone required for OTP")

    # Normalize phone
    if not phone.startswith("+"):
        phone = "+91" + phone[-10:]

    _approval_otps[booking_id] = {
        "otp": otp,
        "phone": phone,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=config.OTP_TTL_SEC),
    }
    logger.info(f"OTP stored for booking {booking_id}")

def verify_otp(booking_id: str, otp: str) -> bool:
    """Verify OTP and return True if valid."""
    entry = _approval_otps.get(booking_id)
    if not entry:
        return False

    if datetime.now(timezone.utc) > entry["exp"]:
        _approval_otps.pop(booking_id, None)
        return False

    # 🔐 Secure compare
    if not hmac.compare_digest(str(entry["otp"]), str(otp)):
        return False

    _approval_otps.pop(booking_id, None)
    return True

def cleanup_expired_otps():
    """Clean up expired OTPs (call periodically)."""
    now = datetime.now(timezone.utc)
    expired = [bid for bid, entry in _approval_otps.items() if now > entry["exp"]]
    for bid in expired:
        _approval_otps.pop(bid, None)
    if expired:
        logger.info(f"Cleaned up {len(expired)} expired OTPs")