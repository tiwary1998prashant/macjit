"""Business logic and domain rules."""
import logging
from datetime import datetime, timezone
from typing import Dict, Optional

from config import config
from database import db
from utils import next_open_slot, shift_within_hours

logger = logging.getLogger(__name__)

async def auto_assign_booking(booking_id: str) -> Optional[dict]:
    """Pick mechanic with earliest free slot + first available bay, set ETA fields."""
    booking = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not booking:
        return None

    # Get service duration
    svc_doc = await db.services.find_one({"key": booking.get("service_type", "general")}, {"_id": 0})
    duration_min = svc_doc["duration_min"] if svc_doc else config.SERVICE_DURATIONS.get(
        booking.get("service_type", "general"), config.DEFAULT_SERVICE_DURATION)

    # Get available mechanics and bays
    mechanics = await db.users.find({"role": "mechanic"}, {"_id": 0}).to_list(100)
    bays = await db.bays.find({}, {"_id": 0}).to_list(100)
    if not mechanics or not bays:
        return None

    now = datetime.now(timezone.utc)

    # Calculate mechanic free times (max of last booking end or now)
    mech_free = {}
    for m in mechanics:
        active = await db.bookings.find(
            {"mechanic_id": m["id"], "status": {"$in": list(config.ACTIVE_STATUSES)}},
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

    # Find earliest available mechanic
    mech_id, (mech, free_at) = min(mech_free.items(), key=lambda kv: kv[1][1])

    # Find first available bay
    busy_bay_ids = set()
    async for b in db.bookings.find(
        {"status": {"$in": list(config.ACTIVE_STATUSES)}}, {"_id": 0, "bay_id": 1}
    ):
        if b.get("bay_id"):
            busy_bay_ids.add(b["bay_id"])
    free_bays = [b for b in bays if b["id"] not in busy_bay_ids]
    bay = free_bays[0] if free_bays else bays[0]  # fallback (will queue)

    # Calculate time slot
    start_at, end_at = shift_within_hours(free_at, duration_min)

    # Update booking
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

async def get_recipients_for_booking(booking: dict, include_customer=True, include_admin=True,
                                     include_reception=True, include_mechanic=True, include_tester=False) -> list[str]:
    """Get list of user IDs to notify for a booking event."""
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