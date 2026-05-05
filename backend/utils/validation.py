"""Input validation utilities."""
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# MongoDB operator injection prevention
_MONGO_OP_RE = re.compile(r"^\$")

def sanitize_str(v: Optional[str], max_len: int = 500) -> Optional[str]:
    """Strip and truncate a string input; reject if it contains MongoDB operator patterns."""
    if v is None:
        return None
    v = str(v).strip()[:max_len]
    if _MONGO_OP_RE.search(v):
        logger.warning(f"Rejected input containing MongoDB operator: {v[:50]}...")
        raise ValueError("Invalid input: contains MongoDB operators")
    return v

def sanitize_value(v):
    """Recursively remove MongoDB operator keys from dicts/lists to prevent NoSQL injection."""
    if isinstance(v, dict):
        return {k: sanitize_value(val) for k, val in v.items() if not _MONGO_OP_RE.match(str(k))}
    if isinstance(v, list):
        return [sanitize_value(i) for i in v]
    return v