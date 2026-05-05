"""Field-level encryption utilities."""
import base64
import hashlib
import hmac
import logging
from typing import Optional
from config import config

logger = logging.getLogger(__name__)

try:
    from cryptography.fernet import Fernet, InvalidToken as FernetInvalidToken
    _cryptography_available = True
except ImportError:
    _cryptography_available = False
    Fernet = None
    FernetInvalidToken = Exception
    logger.warning("cryptography not available, field encryption disabled")

_fernet_instance = None

def _get_fernet():
    global _fernet_instance
    if _fernet_instance is None and config.ENCRYPTION_KEY and _cryptography_available:
        key_bytes = config.ENCRYPTION_KEY.encode()
        # Accept a raw 32-byte key or a 44-char base64 Fernet key
        if len(config.ENCRYPTION_KEY) == 44 and config.ENCRYPTION_KEY.endswith("="):
            fkey = config.ENCRYPTION_KEY.encode()
        else:
            # Pad/truncate to 32 bytes and base64url-encode into a valid Fernet key
            raw = (key_bytes * 4)[:32]
            fkey = base64.urlsafe_b64encode(raw)
        _fernet_instance = Fernet(fkey)
    return _fernet_instance

def encrypt_field(v: Optional[str]) -> Optional[str]:
    """Encrypt a string field; returns 'enc:<base64>' or original if no key."""
    if not v or not isinstance(v, str):
        return v
    f = _get_fernet()
    if not f:
        return v
    return "enc:" + f.encrypt(v.encode()).decode()

def decrypt_field(v: Optional[str]) -> Optional[str]:
    """Decrypt an 'enc:<base64>' field; returns original string or value unchanged."""
    if not v or not isinstance(v, str) or not v.startswith("enc:"):
        return v
    f = _get_fernet()
    if not f:
        return v
    try:
        return f.decrypt(v[4:].encode()).decode()
    except Exception:
        return v

def field_hash(v: str) -> str:
    """Deterministic SHA-256 hash for queryable encrypted fields."""
    salt = config.ENCRYPTION_KEY or "macjit-no-key-salt"
    return hashlib.sha256((salt + (v or "")).encode()).hexdigest()

def decrypt_doc(doc: dict, *fields: str) -> dict:
    """Decrypt named fields in a document dict in-place."""
    if not doc:
        return doc
    for f in fields:
        if f in doc:
            doc[f] = decrypt_field(doc[f])
    return doc