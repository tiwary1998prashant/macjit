"""Shared helpers for server and route modules."""
import json
import logging
import os
import hmac
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Depends, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from config import config
from database import client, db
from utils import (
    decrypt_field,
    encrypt_field,
    field_hash,
    generate_otp,
    rate_check,
    sanitize_str,
    store_otp,
    verify_otp,
    now_iso,
    next_open_slot,
    shift_within_hours,
)
from utils.auth import (
    JWT_ALG,
    JWT_SECRET,
    get_current_user,
    hash_password,
    make_token,
    require_roles,
    security,
    verify_password,
)
from adapters import KafkaAdapter, RabbitAdapter, RazorpayAdapter, TwilioAdapter
from business import auto_assign_booking, get_recipients_for_booking
from events import bus, publish_event
from utils.validation import sanitize_value as _sanitize_value

logger = logging.getLogger("macjit")


def _normalize_phone(p: str) -> str:
    if not p:
        return p
    if not str(p).startswith("+"):
        return "+91" + str(p)[-10:]
    return str(p)
