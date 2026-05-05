"""Event handling and publishing system."""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from config import config
from database import db
from utils import now_iso
from adapters import KafkaAdapter, RabbitAdapter, TwilioAdapter

logger = logging.getLogger(__name__)

class EventBus:
    """Internal event bus for real-time notifications."""
    def __init__(self):
        self.subscribers: Dict[str, List[asyncio.Queue]] = {}

    async def subscribe(self, user_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self.subscribers.setdefault(user_id, []).append(q)
        return q

    def unsubscribe(self, user_id: str, q: asyncio.Queue):
        if user_id in self.subscribers and q in self.subscribers[user_id]:
            self.subscribers[user_id].remove(q)

    async def fanout(self, user_ids: List[str], event: dict):
        """Send event to all subscribers of the given user IDs."""
        for uid in set(user_ids):
            for q in self.subscribers.get(uid, []):
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    pass

# Global event bus instance
bus = EventBus()

# Event templates
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
    if customer_phone and event_type in config.CUSTOMER_NOTIFY_EVENTS:
        msg = EVENT_BODIES.get(event_type, "").format(**_ctx)
        public_url = config.PUBLIC_URL
        plate = booking.get("plate_number", "")
        # For BILLED: include the actual Razorpay payment link
        if event_type == "BILLED":
            pay_link = extra.get("payment_link") or booking.get("payment_link") or ""
            if pay_link:
                msg += f"\nPay securely: {pay_link}"
            elif public_url and plate:
                msg += f"\nTrack & pay: {public_url}/track?plate={plate}"
        await TwilioAdapter.send_whatsapp(customer_phone, msg)