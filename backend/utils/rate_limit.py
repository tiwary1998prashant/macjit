"""Rate limiting utilities."""
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List
from config import config

logger = logging.getLogger(__name__)

# In-memory rate store (in production, use Redis)
_rate_store: Dict[str, List[datetime]] = {}

def rate_check(key: str, limit: int, window_sec: int) -> bool:
    """Returns True if allowed, False if rate limit exceeded."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_sec)
    hits = [t for t in _rate_store.get(key, []) if t > cutoff]
    if len(hits) >= limit:
        logger.warning(f"Rate limit exceeded for {key}")
        return False
    hits.append(now)
    _rate_store[key] = hits
    return True

def cleanup_rate_store():
    """Clean up old rate limit entries (call periodically)."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=1)  # Clean entries older than 1 hour
    for key in list(_rate_store.keys()):
        _rate_store[key] = [t for t in _rate_store[key] if t > cutoff]
        if not _rate_store[key]:
            _rate_store.pop(key, None)