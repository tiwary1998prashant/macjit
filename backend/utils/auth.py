"""Authentication and authorization utilities."""
import asyncio
import jwt
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from config import config
from database import db

logger = logging.getLogger(__name__)

JWT_SECRET = config.JWT_SECRET
JWT_ALG = config.JWT_ALG
security = HTTPBearer(auto_error=False)

async def hash_password(p: str) -> str:
    """Hash a password asynchronously."""
    import bcrypt
    return await asyncio.to_thread(bcrypt.hashpw, p.encode(), bcrypt.gensalt(rounds=10))

async def verify_password(p: str, h: str) -> bool:
    """Verify a password against hash asynchronously."""
    import bcrypt
    try:
        return await asyncio.to_thread(bcrypt.checkpw, p.encode(), h.encode())
    except Exception:
        return False

def make_token(user_id: str, role: str) -> str:
    """Create a JWT token for user."""
    payload = {"sub": user_id, "role": role, "exp": datetime.now(timezone.utc) + timedelta(days=7)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user."""
    if not creds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user

def require_roles(*roles):
    """Dependency to require specific roles."""
    async def checker(user=Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role(s): {','.join(roles)}")
        return user
    return checker