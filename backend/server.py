"""
MacJit - Garage Management System Backend
Async event-driven architecture using internal event bus.
Kafka & RabbitMQ adapters log events; activate by setting KAFKA_BOOTSTRAP / RABBITMQ_URL.
Twilio (WhatsApp/SMS) and Razorpay are stubbed adapters.
"""
import os
import uuid
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta, date
from typing import List, Optional, Dict, Any

import jwt
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, UploadFile, File, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict
import hashlib
import base64
import hmac
import random
import re
try:
    from cryptography.fernet import Fernet, InvalidToken as FernetInvalidToken
    _cryptography_available = True
except ImportError:
    _cryptography_available = False
    Fernet = None
    FernetInvalidToken = Exception

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

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')
logger = logging.getLogger("macjit")

# ---------- DB ----------
mongo_url = os.environ['MONGO_URL'].strip().strip('"').strip("'")
if not (mongo_url.startswith('mongodb://') or mongo_url.startswith('mongodb+srv://')):
    mongo_url = 'mongodb+srv://' + mongo_url
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME'].strip().strip('"').strip("'")]

# ---------- Field-level Encryption ----------
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")
_fernet_instance = None


def _get_fernet():
    global _fernet_instance
    if _fernet_instance is None and ENCRYPTION_KEY and _cryptography_available:
        key_bytes = ENCRYPTION_KEY.encode()
        # Accept a raw 32-byte key or a 44-char base64 Fernet key
        if len(ENCRYPTION_KEY) == 44 and ENCRYPTION_KEY.endswith("="):
            fkey = ENCRYPTION_KEY.encode()
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
    salt = ENCRYPTION_KEY or "macjit-no-key-salt"
    return hashlib.sha256((salt + (v or "")).encode()).hexdigest()


# ---------- NoSQL Injection Prevention ----------
_MONGO_OP_RE = re.compile(r"^\$")

def _sanitize_value(v):
    """Recursively remove MongoDB operator keys from dicts/lists to prevent NoSQL injection."""
    if isinstance(v, dict):
        return {k: _sanitize_value(val) for k, val in v.items() if not _MONGO_OP_RE.match(str(k))}
    if isinstance(v, list):
        return [_sanitize_value(i) for i in v]
    return v


def sanitize_str(v: Optional[str], max_len: int = 500) -> Optional[str]:
    """Strip and truncate a string input; reject if it contains MongoDB operator patterns."""
    if v is None:
        return None
    v = str(v).strip()[:max_len]
    return v


# ---------- OTP Store (in-memory, 10-min TTL) ----------
_approval_otps: Dict[str, dict] = {}  # booking_id -> {otp, phone, exp}
OTP_TTL_SEC = 600  # 10 minutes


def _gen_otp() -> str:
    return str(random.randint(100000, 999999))


def _store_otp(booking_id: str, otp: str, phone: str):
    if not phone:
        raise Exception("Phone required for OTP")

    # Normalize phone
    if not phone.startswith("+"):
        phone = "+91" + phone[-10:]

    _approval_otps[booking_id] = {
        "otp": otp,
        "phone": phone,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=OTP_TTL_SEC),
    }

def _verify_otp(booking_id: str, otp: str) -> bool:
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

   

# ---------- Simple Rate Limiter ----------
_rate_store: Dict[str, list] = {}  # key -> [timestamps]


def _rate_check(key: str, limit: int, window_sec: int) -> bool:
    """Returns True if allowed, False if rate limit exceeded."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_sec)
    hits = [t for t in _rate_store.get(key, []) if t > cutoff]
    if len(hits) >= limit:
        return False
    hits.append(now)
    _rate_store[key] = hits
    return True


def decrypt_doc(doc: dict, *fields: str) -> dict:
    """Decrypt named fields in a document dict in-place."""
    if not doc:
        return doc
    for f in fields:
        if f in doc:
            doc[f] = decrypt_field(doc[f])
    return doc


def public_customer_name(doc: Optional[dict]) -> str:
    """Return the safe display name for a booking/customer document."""
    if not doc:
        return ""
    plain = doc.get("customer_name_plain")
    if plain:
        return plain
    return decrypt_field(doc.get("customer_name")) or ""


def public_booking(doc: Optional[dict]) -> Optional[dict]:
    """Normalize a booking document for API responses."""
    if not doc:
        return doc
    doc["customer_name"] = public_customer_name(doc)
    return doc


def public_bookings(items: list) -> list:
    return [public_booking(b) for b in (items or [])]



# ---------- Auth ----------
JWT_SECRET = os.environ.get('JWT_SECRET', 'macjit-dev-secret-change-in-prod')
JWT_ALG = "HS256"
security = HTTPBearer(auto_error=False)


def _hash_password_sync(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt(rounds=10)).decode()


def _verify_password_sync(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except Exception:
        return False


async def hash_password(p: str) -> str:
    return await asyncio.to_thread(_hash_password_sync, p)


async def verify_password(p: str, h: str) -> bool:
    return await asyncio.to_thread(_verify_password_sync, p, h)


def make_token(user_id: str, role: str) -> str:
    payload = {"sub": user_id, "role": role, "exp": datetime.now(timezone.utc) + timedelta(days=7)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    if not creds:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid token")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(401, "User not found")
    return user


def require_roles(*roles):
    async def checker(user=Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, f"Requires role(s): {','.join(roles)}")
        return user
    return checker


# ---------- Models ----------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LoginIn(BaseModel):
    username: Optional[str] = None
    phone: Optional[str] = None
    password: str


class BookingCreate(BaseModel):
    customer_name: str
    customer_phone: str
    car_make: str
    car_model: str
    plate_number: str
    service_type: str
    notes: Optional[str] = ""


class StaffCreate(BaseModel):
    name: str
    phone: str
    role: str  # mechanic | reception | tester | shopkeeper | admin
    password: Optional[str] = None  # admin sets initial password; if blank, server generates one


class PricingIn(BaseModel):
    service_type: str
    base_price: float


class AssignIn(BaseModel):
    mechanic_id: str
    bay_id: str


class ItemAdd(BaseModel):
    inventory_id: str
    qty: int = 1


class ApprovalReq(BaseModel):
    reason: str
    extra_cost: float = 0.0


class InventoryIn(BaseModel):
    name: str
    sku: str
    category: str
    price: float
    stock: int
    low_stock_threshold: int = 5
    stocked_at: Optional[str] = None
    expiry_at: Optional[str] = None


class BulkInventory(BaseModel):
    items: List[InventoryIn]


class EnquiryIn(BaseModel):
    name: str
    phone: str
    email: Optional[str] = ""
    car_make: Optional[str] = ""
    car_model: Optional[str] = ""
    service_interest: Optional[str] = ""
    message: Optional[str] = ""


class LeaveIn(BaseModel):
    leave_type: str  # casual | earned | sick | unpaid
    start_date: str  # ISO date
    end_date: str
    reason: str = ""


class LeaveDecision(BaseModel):
    decision: str  # approved | rejected
    note: str = ""


class HolidayIn(BaseModel):
    date: str
    name: str
    type: str = "public"  # public | optional


class ProfileUpdate(BaseModel):
    monthly_salary: Optional[float] = None
    designation: Optional[str] = None
    join_date: Optional[str] = None
    leave_balance: Optional[Dict[str, int]] = None  # {casual: 12, earned: 15}


class BonusIn(BaseModel):
    user_id: str
    amount: float
    reason: str
    event_type: str = "bonus"  # bonus | extra_work | salary_credited


class ShopSaleLine(BaseModel):
    inventory_id: str
    qty: int = 1


class ShopSaleIn(BaseModel):
    customer_name: Optional[str] = ""
    customer_phone: Optional[str] = ""
    items: List[ShopSaleLine]
    payment_method: str = "cash"  # cash | razorpay
    fitting_charge: float = 0.0   # labour/fitting charge in ₹
    gst_percent: float = 0.0      # GST percentage, e.g. 18 for 18%


class RefundIn(BaseModel):
    sale_id: str
    reason: str
    items: Optional[List[ShopSaleLine]] = None  # if None → full refund of all sale items




class ServiceIn(BaseModel):
    key: str            # unique slug, e.g. "oil-change"
    name: str           # display label, e.g. "Oil & Filter Change"
    duration_min: int   # estimated duration in minutes
    base_price: float   # base charge (₹)
    active: bool = True

class RefundDecision(BaseModel):
    decision: str  # approved | rejected
    note: str = ""


class UserOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    username: str
    name: str
    role: str
    phone: Optional[str] = None


# ---------- Event Bus + Adapters ----------
class EventBus:
    def __init__(self):
        self.subscribers: Dict[str, List[asyncio.Queue]] = {}  # user_id -> queues

    async def subscribe(self, user_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self.subscribers.setdefault(user_id, []).append(q)
        return q

    def unsubscribe(self, user_id: str, q: asyncio.Queue):
        if user_id in self.subscribers and q in self.subscribers[user_id]:
            self.subscribers[user_id].remove(q)

    async def fanout(self, user_ids: List[str], event: dict):
        for uid in set(user_ids):
            for q in self.subscribers.get(uid, []):
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    pass


bus = EventBus()


class KafkaAdapter:
    """Publishes to Confluent Kafka when KAFKA_BOOTSTRAP/API_KEY/API_SECRET are set."""
    enabled = bool(os.environ.get("KAFKA_BOOTSTRAP") and os.environ.get("KAFKA_API_KEY"))
    _producer = None

    @classmethod
    def _get(cls):
        if cls._producer is None and cls.enabled:
            from confluent_kafka import Producer
            cls._producer = Producer({
                "bootstrap.servers": os.environ["KAFKA_BOOTSTRAP"],
                "security.protocol": "SASL_SSL",
                "sasl.mechanisms": "PLAIN",
                "sasl.username": os.environ["KAFKA_API_KEY"],
                "sasl.password": os.environ["KAFKA_API_SECRET"],
            })
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


class RabbitAdapter:
    """Publishes to CloudAMQP when RABBITMQ_URL is set."""
    enabled = bool(os.environ.get("RABBITMQ_URL"))
    _conn = None

    @classmethod
    async def _channel(cls):
        if cls._conn is None and cls.enabled:
            import aio_pika
            cls._conn = await aio_pika.connect_robust(os.environ["RABBITMQ_URL"])
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


class TwilioAdapter:
    enabled = bool(os.environ.get("TWILIO_ACCOUNT_SID") and os.environ.get("TWILIO_AUTH_TOKEN"))

    @classmethod
    async def _post(cls, body_data: dict):
        import httpx
        sid = os.environ["TWILIO_ACCOUNT_SID"]
        tok = os.environ["TWILIO_AUTH_TOKEN"]
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        async with httpx.AsyncClient(timeout=10) as cli:
            r = await cli.post(url, data=body_data, auth=(sid, tok))
            return r.status_code, r.text

    @classmethod
    async def send_whatsapp(cls, to: str, body: str):
        if cls.enabled:
            try:
                from_num = os.environ.get("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886").strip()
                if not from_num.startswith("whatsapp:"):
                    from_num = "whatsapp:" + from_num
                code, body_resp = await cls._post({"From": from_num, "To": f"whatsapp:{to}", "Body": body})
                logger.info(f"[TWILIO-WA->{to}] {code} {body_resp[:200] if code >= 400 else ''}")
            except Exception as e:
                logger.error(f"[TWILIO-WA-ERR] {e}")
        else:
            logger.info(f"[TWILIO-WA-MOCK->{to}] {body[:80]}")

    @classmethod
    async def send_sms(cls, to: str, body: str):
        if not cls.enabled:
            logger.warning("Twilio not configured")
            return

        try:
            import httpx

            if not to.startswith("+"):
                to = "+91" + to[-10:]

            from_num = os.environ.get("TWILIO_SMS_FROM")

            async with httpx.AsyncClient(timeout=10) as cli:
                r = await cli.post(
                    f"https://api.twilio.com/2010-04-01/Accounts/{os.environ['TWILIO_ACCOUNT_SID']}/Messages.json",
                    data={"From": from_num, "To": to, "Body": body},
                    auth=(os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"]),
                )

                if r.status_code >= 400:
                    logger.error(f"[TWILIO ERROR] {r.status_code} {r.text}")
                else:
                    logger.info(f"[SMS SENT] {to}")

        except Exception as e:
            logger.error(f"[TWILIO EXCEPTION] {e}")

        if cls.enabled:
            try:
                from_num = os.environ.get("TWILIO_SMS_FROM", "+15005550006")
                code, _ = await cls._post({"From": from_num, "To": to, "Body": body})
                logger.info(f"[TWILIO-SMS->{to}] {code}")
            except Exception as e:
                logger.error(f"[TWILIO-SMS-ERR] {e}")
        else:
            logger.info(f"[TWILIO-SMS-MOCK->{to}] {body[:80]}")


class RazorpayAdapter:
    enabled = bool(os.environ.get("RAZORPAY_KEY_ID") and os.environ.get("RAZORPAY_KEY_SECRET"))
    WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")

    @classmethod
    async def create_payment_link_full(cls, amount: float, ref_id: str, customer_phone: str = "",
                                        notes: Optional[Dict[str, Any]] = None) -> tuple:
        if not cls.enabled:
            raise Exception("Razorpay not configured. Check env variables.")

        try:
            import httpx

            # Ensure phone format
            if customer_phone and not customer_phone.startswith("+"):
                customer_phone = "+91" + customer_phone[-10:]

            payload = {
                "amount": int(amount * 100),
                "currency": "INR",
                "description": f"MacJit #{ref_id[:8]}",
                "customer": {"contact": customer_phone} if customer_phone else {},
                "notify": {"sms": True, "email": False},
                "notes": {**(notes or {}), "ref_id": ref_id},
            }

            async with httpx.AsyncClient(timeout=15) as cli:
                r = await cli.post(
                    "https://api.razorpay.com/v1/payment_links",
                    json=payload,
                    auth=(os.environ["RAZORPAY_KEY_ID"], os.environ["RAZORPAY_KEY_SECRET"]),
                )

                # 🔥 CRITICAL FIX
                if r.status_code >= 400:
                    logger.error(f"[RAZORPAY ERROR] {r.status_code} {r.text}")
                    raise Exception(f"Razorpay API failed: {r.text}")

                data = r.json()

                if not data.get("short_url"):
                    raise Exception(f"Invalid Razorpay response: {data}")

                return data["short_url"], data.get("id", "")

        except Exception as e:
            logger.error(f"[RAZORPAY-EXCEPTION] {e}")
            raise HTTPException(500, f"Payment link generation failed: {str(e)}")


# ---------- Event Pipeline ----------
async def publish_event(event_type: str, booking: dict, recipients: List[str], extra: dict = None):
    """Single point that: stores event, fans out via WebSocket, calls Kafka/Rabbit/Twilio adapters."""
    extra = extra or {}
    event = {
        "id": str(uuid.uuid4()),
        "type": event_type,
        "booking_id": booking.get("id"),
        "ts": now_iso(),
        "data": {**{k: v for k, v in booking.items() if k != "_id"}, **extra},
    }
    await db.events.insert_one(dict(event))
    event.pop("_id", None)

    # Build template context once (used for both notif body and Twilio msg)
    _mech = booking.get("mechanic_name") or "our team"
    _tester = booking.get("tester_name") or ""
    _qa_reasons = booking.get("qa_fail_reasons") or []
    _ctx = {
        "plate": booking.get("plate_number", ""),
        "id": (booking.get("id") or "")[:6],
        "mechanic": _mech,
        "tester": _tester,
        "tester_part": f" by {_tester}" if _tester else "",
        "qa_fail_reasons": ", ".join(_qa_reasons) if _qa_reasons else "—",
    }

    # Notifications stored per recipient
    for uid in set(recipients):
        notif = {
            "id": str(uuid.uuid4()),
            "user_id": uid,
            "event_type": event_type,
            "booking_id": booking.get("id"),
            "title": EVENT_TITLES.get(event_type, event_type),
            "body": EVENT_BODIES.get(event_type, "").format(**_ctx),
            "read": False,
            "ts": now_iso(),
        }
        await db.notifications.insert_one(dict(notif))

    await bus.fanout(recipients, event)

    # Adapter side-effects
    await KafkaAdapter.publish("garage.events", event)
    await RabbitAdapter.enqueue(f"queue.{event_type.lower()}", event)

    # Twilio for customer-facing transitions (read phone directly from booking)
    customer_phone = booking.get("customer_phone")
    if customer_phone and event_type in CUSTOMER_NOTIFY_EVENTS:
        msg = EVENT_BODIES.get(event_type, "").format(**_ctx)
        public_url = os.environ.get("PUBLIC_URL") or os.environ.get("APP_URL") or ""
        plate = booking.get("plate_number", "")
        # For BILLED: include the actual Razorpay payment link
        if event_type == "BILLED":
            pay_link = extra.get("payment_link") or booking.get("payment_link") or ""
            if pay_link:
                msg += f"\nPay securely: {pay_link}"
            elif public_url and plate:
                msg += f"\nTrack & pay: {public_url}/track?plate={plate}"
        elif public_url and plate:
            msg += f"\nTrack & pay: {public_url}/track?plate={plate}"
        await TwilioAdapter.send_whatsapp(customer_phone, msg)


EVENT_TITLES = {
    "BOOKING_CREATED": "New Booking",
    "BOOKING_ASSIGNED": "Vehicle Assigned",
    "SERVICE_STARTED": "Service Started",
    "APPROVAL_REQUESTED": "Approval Needed",
    "APPROVAL_GRANTED": "Customer Approved",
    "SERVICE_FINISHED": "Service Finished",
    "QA_DONE": "QA Done - Ready for Pickup",
    "QA_FAIL": "QA Failed - Returned to Mechanic",
    "BILLED": "Bill Generated",
    "PAID": "Payment Received",
}
EVENT_BODIES = {
    "BOOKING_CREATED": "MacJit: Booking #{id} for {plate} confirmed. Mechanic {mechanic} will handle your car.",
    "BOOKING_ASSIGNED": "MacJit: Your car {plate} is assigned to mechanic {mechanic}.",
    "SERVICE_STARTED": "MacJit: Service started on {plate} by {mechanic}. We'll keep you posted.",
    "APPROVAL_REQUESTED": "MacJit: {mechanic} needs your approval for extra work on {plate}. Please open the app.",
    "APPROVAL_GRANTED": "MacJit: Approval received for extra work on {plate}.",
    "SERVICE_FINISHED": "MacJit: {mechanic} finished work on {plate}. Now in QA.",
    "QA_DONE": "MacJit: {plate} passed QA{tester_part}. Ready for pickup!",
    "QA_FAIL": "MacJit: QA FAILED for {plate}. Reason(s): {qa_fail_reasons}. Please fix and resubmit.",
    "BILLED": "MacJit: Bill for {plate} generated. Payment link sent on WhatsApp/SMS.",
    "PAID": "MacJit: Payment received for {plate}. Thanks for choosing us — drive safe!",
}
CUSTOMER_NOTIFY_EVENTS = {"BOOKING_CREATED", "SERVICE_STARTED", "APPROVAL_REQUESTED",
                          "SERVICE_FINISHED", "QA_DONE", "BILLED", "PAID"}

# ---------- Auto-Assignment (8am-6pm service window) ----------
SERVICE_DURATION_MIN = 120  # default fallback
SERVICE_DURATION_BY_TYPE = {
    "oil-change": 45,
    "general": 120,        # 2h
    "ac-service": 90,
    "alignment": 60,
    "brake": 75,
    "engine": 240,         # 4h
    "full-service": 210,   # 3h 30m
}
SHOP_OPEN_HOUR = 8
SHOP_CLOSE_HOUR = 18  # 6 PM
ACTIVE_STATUSES = {"ASSIGNED", "IN_SERVICE"}


def _next_open_slot(after: datetime) -> datetime:
    """Snap a datetime forward to next 8:00-18:00 working window."""
    dt = after
    if dt.hour < SHOP_OPEN_HOUR:
        dt = dt.replace(hour=SHOP_OPEN_HOUR, minute=0, second=0, microsecond=0)
    elif dt.hour >= SHOP_CLOSE_HOUR:
        dt = (dt + timedelta(days=1)).replace(hour=SHOP_OPEN_HOUR, minute=0, second=0, microsecond=0)
    return dt


def _shift_within_hours(start: datetime, duration_min: int) -> tuple:
    """If the slot crosses 18:00, push start to next day 08:00."""
    start = _next_open_slot(start)
    end = start + timedelta(minutes=duration_min)
    close_today = start.replace(hour=SHOP_CLOSE_HOUR, minute=0, second=0, microsecond=0)
    if end > close_today:
        start = (start + timedelta(days=1)).replace(hour=SHOP_OPEN_HOUR, minute=0, second=0, microsecond=0)
        end = start + timedelta(minutes=duration_min)
    return start, end


async def auto_assign_booking(booking_id: str) -> Optional[dict]:
    """Pick mechanic with earliest free slot + first available bay, set ETA fields."""
    booking = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not booking:
        return None
    svc_doc = await db.services.find_one({"key": booking.get("service_type", "general")}, {"_id": 0})
    duration_min = svc_doc["duration_min"] if svc_doc else SERVICE_DURATION_BY_TYPE.get(booking.get("service_type", "general"), SERVICE_DURATION_MIN)
    mechanics = await db.users.find({"role": "mechanic"}, {"_id": 0}).to_list(100)
    bays = await db.bays.find({}, {"_id": 0}).to_list(100)
    if not mechanics or not bays:
        return None

    now = datetime.now(timezone.utc)
    # mechanic free time = max(end of last assigned/in-service booking, now)
    mech_free = {}
    for m in mechanics:
        active = await db.bookings.find(
            {"mechanic_id": m["id"], "status": {"$in": list(ACTIVE_STATUSES)}},
            {"_id": 0}
        ).to_list(100)
        latest_end = now
        for b in active:
            est = b.get("estimated_end_at")
            if est:
                try:
                    end_dt = datetime.fromisoformat(est)
                    if end_dt > latest_end:
                        latest_end = end_dt
                except ValueError:
                    pass
        mech_free[m["id"]] = (m, latest_end)

    # earliest free mechanic
    mech_id, (mech, free_at) = min(mech_free.items(), key=lambda kv: kv[1][1])

    # first bay not currently occupied
    busy_bay_ids = set()
    async for b in db.bookings.find(
        {"status": {"$in": list(ACTIVE_STATUSES)}}, {"_id": 0, "bay_id": 1}
    ):
        if b.get("bay_id"):
            busy_bay_ids.add(b["bay_id"])
    free_bays = [b for b in bays if b["id"] not in busy_bay_ids]
    bay = free_bays[0] if free_bays else bays[0]  # fallback (will queue)

    start_at, end_at = _shift_within_hours(free_at, duration_min)
    upd = {
        "mechanic_id": mech["id"], "mechanic_name": mech["name"],
        "mechanic_phone": mech.get("phone"),
        "bay_id": bay["id"], "bay_name": bay["name"],
        "status": "ASSIGNED",
        "estimated_start_at": start_at.isoformat(),
        "estimated_end_at": end_at.isoformat(),
        "estimated_duration_min": duration_min,
        "auto_assigned": True,
    }
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    return await db.bookings.find_one({"id": booking_id}, {"_id": 0})



# ---------- App Setup ----------
docs_enabled = os.environ.get("ENABLE_API_DOCS", "0").strip().lower() in ("1", "true", "yes", "on")
app = FastAPI(
    title="MacJit GMS",
    docs_url="/api/docs" if docs_enabled else None,
    redoc_url="/api/redoc" if docs_enabled else None,
    openapi_url="/api/openapi.json" if docs_enabled else None,
)

async def get_recipients_for_booking(booking: dict, include_customer=True, include_admin=True,
                                     include_reception=True, include_mechanic=True, include_tester=False) -> List[str]:
    """Customers no longer have login accounts so include_customer is now ignored;
    customer notifications are sent over WhatsApp via Twilio (see publish_event)."""
    ids = []
    if booking.get("mechanic_id") and include_mechanic:
        ids.append(booking["mechanic_id"])
    role_filter = []
    if include_reception:
        role_filter.append("reception")
    if include_admin:
        role_filter.append("admin")
    if include_tester:
        role_filter.append("tester")
    if role_filter:
        async for u in db.users.find({"role": {"$in": role_filter}}, {"_id": 0, "id": 1}):
            ids.append(u["id"])
    return ids




# OTP login removed — customers now track via vehicle plate, no auth.




async def _send_sale_invoice_whatsapp(sale: dict):
    """Build a formatted invoice from a sale doc and send it via Twilio WhatsApp."""
    phone = sale.get("customer_phone", "")
    if not phone:
        return
    items = sale.get("items", [])
    inv_lines = "\n".join(f"  {it['name']} x{it['qty']} = \u20b9{it['subtotal']:.0f}" for it in items)
    fitting = float(sale.get("fitting_charge") or 0)
    gst_pct = float(sale.get("gst_percent") or 0)
    gst_amt = float(sale.get("gst_amount") or 0)
    grand = float(sale.get("total", 0))
    fitting_line = f"\n  Fitting charge = \u20b9{fitting:.0f}" if fitting > 0 else ""
    gst_line = f"\n  GST ({gst_pct}%) = \u20b9{gst_amt:.0f}" if gst_amt > 0 else ""
    msg = (
        f"*MacJit Invoice #{sale['id'][:8]}*\n"
        f"{inv_lines}{fitting_line}{gst_line}\n"
        f"*Total = \u20b9{grand:.0f}*\n"
        f"Payment: {sale.get('payment_method','cash').upper()} — PAID \u2705\nThank you! \U0001f697"
    )
    await TwilioAdapter.send_whatsapp(phone, msg)


# ---------- Razorpay Webhook ----------
@app.post("/api/webhooks/razorpay")
async def razorpay_webhook(request: Request):
    """
    Razorpay sends POST with X-Razorpay-Signature header.
    Events handled:
      - payment_link.paid    → mark shop sale paid + send invoice via WhatsApp
      - payment.captured     → same fallback lookup
      - payment.authorized   → for bookings: mark booking as paid
    Configure in Razorpay Dashboard → Settings → Webhooks → Add URL:
        https://<your-domain>/api/webhooks/razorpay
    Secret: set RAZORPAY_WEBHOOK_SECRET env var (same as dashboard).
    """
    body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature", "")

    if not RazorpayAdapter.verify_webhook_signature(body, signature):
        logger.warning("[RAZORPAY-WEBHOOK] Invalid signature — rejected")
        raise HTTPException(400, "Invalid webhook signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")

    event = payload.get("event", "")
    logger.info(f"[RAZORPAY-WEBHOOK] event={event}")

    # ---- payment_link.paid (primary event for payment links) ----
    if event == "payment_link.paid":
        pl_entity = payload.get("payload", {}).get("payment_link", {}).get("entity", {})
        rzp_link_id = pl_entity.get("id", "")
        notes = pl_entity.get("notes") or {}
        ref_id = notes.get("ref_id") or notes.get("sale_id") or ""
        txn_type = notes.get("type", "")
        rzp_payment_id = payload.get("payload", {}).get("payment", {}).get("entity", {}).get("id", "")
        amount_paise = pl_entity.get("amount_paid") or pl_entity.get("amount") or 0
        amount = amount_paise / 100

        logger.info(f"[RAZORPAY-WEBHOOK] payment_link.paid link={rzp_link_id} ref={ref_id} type={txn_type} payment_id={rzp_payment_id}")

        if txn_type == "shop_sale" or not txn_type:
            # Try lookup by rzp_payment_link_id first, then by sale_id in notes
            sale = None
            if rzp_link_id:
                sale = await db.shop_sales.find_one({"rzp_payment_link_id": rzp_link_id}, {"_id": 0})
            if not sale and ref_id:
                sale = await db.shop_sales.find_one({"id": ref_id}, {"_id": 0})
            if sale and not sale.get("paid"):
                now_ts = now_iso()
                await db.shop_sales.update_one({"id": sale["id"]}, {"$set": {
                    "paid": True,
                    "paid_at": now_ts,
                    "rzp_payment_id": rzp_payment_id,
                    "rzp_amount_received": amount,
                }})
                sale["paid"] = True
                sale["paid_at"] = now_ts
                # Send formatted WhatsApp invoice
                await _send_sale_invoice_whatsapp(sale)
                # Notify admin/shopkeeper via WebSocket
                admin_ids = [u["id"] async for u in db.users.find({"role": {"$in": ["admin", "shopkeeper"]}}, {"_id": 0, "id": 1})]
                await bus.fanout(admin_ids, {
                    "type": "SHOP_PAYMENT_RECEIVED",
                    "data": {"sale_id": sale["id"], "amount": amount, "payment_id": rzp_payment_id},
                    "ts": now_iso()
                })
                logger.info(f"[RAZORPAY-WEBHOOK] Shop sale {sale['id']} marked PAID — invoice sent to {sale.get('customer_phone')}")
            elif sale and sale.get("paid"):
                logger.info(f"[RAZORPAY-WEBHOOK] Sale {sale.get('id')} already marked paid — skipping")
            else:
                logger.warning(f"[RAZORPAY-WEBHOOK] Could not find shop sale for link={rzp_link_id} ref={ref_id}")

        elif txn_type == "service_booking":
            booking_id = notes.get("booking_id") or ref_id
            booking = None
            if rzp_link_id:
                booking = await db.bookings.find_one({"rzp_payment_link_id": rzp_link_id}, {"_id": 0})
            if not booking and booking_id:
                booking = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
            if booking and not booking.get("paid"):
                await db.bookings.update_one({"id": booking["id"]}, {"$set": {
                    "paid": True,
                    "status": "PAID",
                    "paid_at": now_iso(),
                    "payment_method": "razorpay",
                    "razorpay_payment_id": rzp_payment_id,
                }})
                updated = await db.bookings.find_one({"id": booking["id"]}, {"_id": 0})
                recipients = await get_recipients_for_booking(updated)
                await publish_event("PAID", updated, recipients)
                # Also send SMS invoice to customer
                c_phone = updated.get("customer_phone")
                if c_phone:
                    pub = os.environ.get("PUBLIC_URL") or os.environ.get("APP_URL") or ""
                    inv_url = f"{pub}/api/invoices/{updated['id']}.pdf"
                    await TwilioAdapter.send_sms(c_phone, f"MacJit: Payment of \u20B9{updated.get('bill_amount',0)} received for {updated.get('plate_number','')}. Invoice: {inv_url}")
                logger.info(f"[RAZORPAY-WEBHOOK] Booking {booking['id']} marked PAID")
            elif booking:
                logger.info(f"[RAZORPAY-WEBHOOK] Booking already paid — skipping")

    # ---- payment.captured (fallback for orders / older flows) ----
    elif event == "payment.captured":
        payment = payload.get("payload", {}).get("payment", {}).get("entity", {})
        rzp_payment_id = payment.get("id", "")
        notes = payment.get("notes") or {}
        ref_id = notes.get("ref_id") or ""
        txn_type = notes.get("type", "")
        amount = (payment.get("amount") or 0) / 100

        if txn_type == "shop_sale" and ref_id:
            sale = await db.shop_sales.find_one({"id": ref_id}, {"_id": 0})
            if sale and not sale.get("paid"):
                await db.shop_sales.update_one({"id": ref_id}, {"$set": {
                    "paid": True, "paid_at": now_iso(),
                    "rzp_payment_id": rzp_payment_id,
                    "rzp_amount_received": amount,
                }})
                sale["paid"] = True
                await _send_sale_invoice_whatsapp(sale)
                logger.info(f"[RAZORPAY-WEBHOOK] payment.captured → shop sale {ref_id} PAID")

    return {"status": "ok"}


@app.get("/api/webhooks/razorpay/redirect")
async def razorpay_redirect(razorpay_payment_id: Optional[str] = None,
                             razorpay_payment_link_id: Optional[str] = None,
                             razorpay_payment_link_status: Optional[str] = None,
                             razorpay_signature: Optional[str] = None):
    """
    Razorpay callback redirect after customer completes payment on the payment page.
    Razorpay appends query params: razorpay_payment_id, razorpay_payment_link_id,
    razorpay_payment_link_status, razorpay_signature.
    We verify the signature and mark the sale/booking paid immediately (no wait for webhook).
    """
    from fastapi.responses import RedirectResponse

    if razorpay_payment_link_status != "paid":
        logger.info(f"[RAZORPAY-REDIRECT] status={razorpay_payment_link_status} — not paid yet")
        return RedirectResponse(url=os.environ.get("PUBLIC_URL", "/") + "?payment=cancelled")

    # Verify redirect signature: HMAC-SHA256(payment_link_id|payment_link_reference_id|payment_link_status|payment_id)
    if RazorpayAdapter.WEBHOOK_SECRET and razorpay_payment_id and razorpay_payment_link_id:
        msg = f"{razorpay_payment_link_id}|{razorpay_payment_link_id}|{razorpay_payment_link_status}|{razorpay_payment_id}"
        expected = hmac.new(RazorpayAdapter.WEBHOOK_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, razorpay_signature or ""):
            logger.warning("[RAZORPAY-REDIRECT] Signature mismatch")
            raise HTTPException(400, "Invalid signature")

    # Find and mark sale paid by rzp_payment_link_id
    if razorpay_payment_link_id:
        sale = await db.shop_sales.find_one({"rzp_payment_link_id": razorpay_payment_link_id}, {"_id": 0})
        if sale and not sale.get("paid"):
            await db.shop_sales.update_one({"id": sale["id"]}, {"$set": {
                "paid": True, "paid_at": now_iso(),
                "rzp_payment_id": razorpay_payment_id,
            }})
            sale["paid"] = True
            await _send_sale_invoice_whatsapp(sale)
            logger.info(f"[RAZORPAY-REDIRECT] Sale {sale['id']} marked paid via redirect")
        # Also check bookings
        booking = await db.bookings.find_one({"rzp_payment_link_id": razorpay_payment_link_id}, {"_id": 0})
        if booking and not booking.get("paid"):
            await db.bookings.update_one({"id": booking["id"]}, {"$set": {
                "paid": True, "status": "PAID", "paid_at": now_iso(),
                "payment_method": "razorpay", "razorpay_payment_id": razorpay_payment_id,
            }})
            updated = await db.bookings.find_one({"id": booking["id"]}, {"_id": 0})
            recipients = await get_recipients_for_booking(updated)
            await publish_event("PAID", updated, recipients)
            logger.info(f"[RAZORPAY-REDIRECT] Booking {booking['id']} marked paid via redirect")

    return RedirectResponse(url=os.environ.get("PUBLIC_URL", "/") + "?payment=success")

# ---------- WebSocket ----------
@app.websocket("/api/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload["sub"]
    except jwt.PyJWTError:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    q = await bus.subscribe(user_id)
    try:
        await websocket.send_json({"type": "connected", "user_id": user_id})
        while True:
            event = await q.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"ws error: {e}")
    finally:
        bus.unsubscribe(user_id, q)


# ---------- Seeding ----------
# SECURITY NOTE: Admin seeding is DISABLED by default for security.
# To enable admin seeding, set SEED_ADMIN=true and configure ADMIN_* environment variables.
# This prevents accidental creation of default admin accounts in production.

# Only seed admin if explicitly enabled
SEED_ADMIN = os.environ.get('SEED_ADMIN', '').lower() == 'true'

if SEED_ADMIN:
    DEFAULT_ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
    DEFAULT_ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
    DEFAULT_ADMIN_NAME = os.environ.get('ADMIN_NAME')
    DEFAULT_ADMIN_PHONE = os.environ.get('ADMIN_PHONE')

    if not all([DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_NAME, DEFAULT_ADMIN_PHONE]):
        logger.error("SEED_ADMIN=true but ADMIN_* environment variables not set. Skipping admin seeding.")
        DEMO_USERS = []
    else:
        DEMO_USERS = [{
            "username": DEFAULT_ADMIN_USERNAME,
            "password": DEFAULT_ADMIN_PASSWORD,
            "name": DEFAULT_ADMIN_NAME,
            "role": "admin",
            "phone": DEFAULT_ADMIN_PHONE
        }]
        logger.info("Admin seeding enabled via SEED_ADMIN=true")
else:
    DEMO_USERS = []
    logger.info("Admin seeding disabled (set SEED_ADMIN=true to enable)")

DEMO_BAYS = [
    {"id": "bay-1", "name": "Bay A1", "type": "general"},
    {"id": "bay-2", "name": "Bay A2", "type": "general"},
    {"id": "bay-3", "name": "Bay B1", "type": "engine"},
    {"id": "bay-4", "name": "Bay B2", "type": "tire"},
]

DEMO_INVENTORY = [
    {"name": "Engine Oil 5W-30 Synthetic 4L (Castrol)", "sku": "OIL-CST-4L-5W30", "category": "Lubricants", "price": 2400, "stock": 18, "low_stock_threshold": 6,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=20)).isoformat(),
     "expiry_at": (datetime.now(timezone.utc) + timedelta(days=540)).isoformat()},
    {"name": "Engine Oil 0W-20 Synthetic 4L (Mobil1)", "sku": "OIL-MBL-4L-0W20", "category": "Lubricants", "price": 3200, "stock": 10, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=15)).isoformat(),
     "expiry_at": (datetime.now(timezone.utc) + timedelta(days=600)).isoformat()},
    {"name": "Oil Filter (Bosch)", "sku": "FLT-OIL-BSH", "category": "Filters", "price": 480, "stock": 22, "low_stock_threshold": 6,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=12)).isoformat()},
    {"name": "Air Filter (Bosch)", "sku": "FLT-AIR-BSH", "category": "Filters", "price": 620, "stock": 14, "low_stock_threshold": 5,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()},
    {"name": "Cabin AC Filter (carbon)", "sku": "FLT-AC-CRB", "category": "Filters", "price": 850, "stock": 9, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=18)).isoformat()},
    {"name": "Front Brake Pad Set (Bosch)", "sku": "BRK-PAD-FRT", "category": "Brakes", "price": 1850, "stock": 6, "low_stock_threshold": 3,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=22)).isoformat()},
    {"name": "Rear Brake Shoe Set", "sku": "BRK-SHOE-RR", "category": "Brakes", "price": 1450, "stock": 4, "low_stock_threshold": 3,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=25)).isoformat()},
    {"name": "Brake Fluid DOT-4 1L", "sku": "FLD-BRK-DOT4", "category": "Fluids", "price": 380, "stock": 16, "low_stock_threshold": 5,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()},
    {"name": "Coolant 5L (pre-mix)", "sku": "COL-5L", "category": "Fluids", "price": 950, "stock": 12, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()},
    {"name": "Wiper Blade Set 22\"+18\"", "sku": "WIP-22-18", "category": "Wipers", "price": 850, "stock": 8, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()},
    {"name": "12V 65Ah Battery (Exide)", "sku": "BAT-EXD-65", "category": "Battery", "price": 7200, "stock": 5, "low_stock_threshold": 2,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=18)).isoformat()},
    {"name": "Spark Plug Set of 4 (NGK Iridium)", "sku": "SPK-NGK-IR-4", "category": "Ignition", "price": 1600, "stock": 12, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=11)).isoformat()},
    {"name": "AC Refrigerant Gas R-1234yf 250g", "sku": "AC-GAS-R1234", "category": "AC", "price": 2800, "stock": 6, "low_stock_threshold": 3,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()},
    {"name": "Tyre 195/55 R16 (Apollo)", "sku": "TYR-195-55-16", "category": "Tyres", "price": 7200, "stock": 8, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=25)).isoformat()},
]


@app.on_event("startup")
async def startup():
    # One-time cleanup: remove any old hard-coded demo accounts from earlier seeds
    OLD_DEMO_USERNAMES = ["customer", "customer2", "reception", "mechanic",
                          "mechanic2", "tester", "admin", "shopkeeper"]
    deleted = await db.users.delete_many({"username": {"$in": OLD_DEMO_USERNAMES}})
    if deleted.deleted_count:
        logger.info(f"Cleaned up {deleted.deleted_count} legacy demo users")
    # Customers no longer have accounts — purge any leftovers from older builds.
    cust_purged = await db.users.delete_many({"role": "customer"})
    if cust_purged.deleted_count:
        logger.info(f"Purged {cust_purged.deleted_count} legacy customer accounts (customers no longer log in)")
    # Drop OTP collection if present (feature removed)
    try:
        await db.otps.drop()
    except Exception:
        pass
    # One-time cleanup: remove old 2-wheeler demo inventory
    OLD_INV_SKUS = ["OIL-CST-1L", "BRK-PAD-01", "FLT-AIR-01", "SPK-NGK-01",
                    "CHN-LUB-01", "TYR-90-17", "COL-500"]
    inv_del = await db.inventory.delete_many({"sku": {"$in": OLD_INV_SKUS}})
    if inv_del.deleted_count:
        logger.info(f"Cleaned up {inv_del.deleted_count} legacy 2-wheeler inventory items")
    # Idempotently seed/upgrade demo users (force admin role + correct password hash)
    if DEMO_USERS:
        for u in DEMO_USERS:
            existing = await db.users.find_one({"username": u["username"]})
            h = await hash_password(u["password"])
            if existing:
                # Update existing admin user
                update_data = {"name": u["name"], "role": u["role"], "phone": u["phone"], "password_hash": h}
                # If password changed, force reset
                if not existing.get("must_reset_password"):
                    update_data["must_reset_password"] = True
                await db.users.update_one(
                    {"id": existing["id"]},
                    {"$set": update_data}
                )
                logger.info(f"Upgraded existing user {u['username']} to {u['role']}")
            else:
                # Create new admin user with forced password reset
                doc = {"id": str(uuid.uuid4()), "username": u["username"], "name": u["name"],
                       "role": u["role"], "phone": u["phone"],
                       "password_hash": h, "created_at": now_iso(),
                       "must_reset_password": True}
                await db.users.insert_one(doc)  # seed users stored without encryption
                logger.warning(f"*** SECURITY WARNING *** Seeded admin user {u['username']} with password from environment variables. CHANGE IMMEDIATELY after first login!")
    else:
        logger.info("No admin users to seed (admin seeding disabled)")

    DEMO_SERVICES = [
        {"key": "general", "name": "General Service", "duration_min": 120, "base_price": 1200, "active": True},
        {"key": "oil-change", "name": "Oil & Filter Change", "duration_min": 45, "base_price": 800, "active": True},
        {"key": "full-service", "name": "Full Service", "duration_min": 210, "base_price": 3500, "active": True},
        {"key": "ac-service", "name": "AC Service", "duration_min": 90, "base_price": 1500, "active": True},
        {"key": "alignment", "name": "Wheel Alignment & Balancing", "duration_min": 60, "base_price": 700, "active": True},
        {"key": "brake", "name": "Brake Service", "duration_min": 75, "base_price": 1000, "active": True},
        {"key": "engine", "name": "Engine Repair / Diagnostics", "duration_min": 240, "base_price": 2500, "active": True},
    ]
    if await db.services.count_documents({}) == 0:
        for s in DEMO_SERVICES:
            await db.services.insert_one({"id": str(uuid.uuid4()), **s, "created_at": now_iso()})
        logger.info(f"Seeded {len(DEMO_SERVICES)} default services")

    if await db.bays.count_documents({}) == 0:
        for b in DEMO_BAYS:
            await db.bays.insert_one({**b, "created_at": now_iso()})
        logger.info(f"Seeded {len(DEMO_BAYS)} bays")
    if await db.inventory.count_documents({}) == 0:
        for i in DEMO_INVENTORY:
            await db.inventory.insert_one({"id": str(uuid.uuid4()), **i, "created_at": now_iso()})
        logger.info(f"Seeded {len(DEMO_INVENTORY)} inventory items")


@app.on_event("shutdown")
async def shutdown():
    client.close()


from routes import routers

for router in routers:
    app.include_router(router, prefix="/api")

cors_origins_raw = os.environ.get("CORS_ORIGINS", "").strip()
cors_origins = [origin.strip() for origin in cors_origins_raw.split(",") if origin.strip()]
if not cors_origins:
    logger.warning("CORS_ORIGINS is empty. No browser origins will be allowed.")
    cors_origins = []

allowed_hosts_raw = os.environ.get("ALLOWED_HOSTS", "").strip()
allowed_hosts = [host.strip() for host in allowed_hosts_raw.split(",") if host.strip()]
if allowed_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

if os.environ.get("FORCE_HTTPS", "0").strip().lower() in ("1", "true", "yes", "on"):
    app.add_middleware(HTTPSRedirectMiddleware)

cors_allow_credentials = bool(cors_origins) and cors_origins != ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=cors_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ---------- Security Headers Middleware ----------
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ---------- Serve React frontend (production build) ----------
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

FRONTEND_BUILD = ROOT_DIR.parent / "frontend" / "build"
NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}

def _serve_index():
    return FileResponse(str(FRONTEND_BUILD / "index.html"), headers=NO_CACHE_HEADERS)

if FRONTEND_BUILD.exists():
    static_dir = FRONTEND_BUILD / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/")
    async def _spa_root():
        return _serve_index()

    @app.get("/{full_path:path}")
    async def _spa_fallback(full_path: str):
        if (full_path.startswith("api")
                or full_path.startswith("ws")
                or full_path.startswith("__replco")
                or full_path.startswith("__replit")):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        candidate = FRONTEND_BUILD / full_path
        if candidate.exists() and candidate.is_file():
            # Disable caching for the service worker and the HTML shell so
            # browsers always pick up the latest build.
            if full_path in ("sw.js", "index.html", "manifest.json"):
                return FileResponse(str(candidate), headers=NO_CACHE_HEADERS)
            return FileResponse(str(candidate))
        return _serve_index()
else:
    @app.get("/")
    async def _no_build():
        return JSONResponse({
            "status": "backend_only",
            "message": "Frontend build not found. Run `cd frontend && yarn build`.",
        })
