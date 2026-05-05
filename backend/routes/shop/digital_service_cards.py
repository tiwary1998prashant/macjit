from server import BaseModel, Depends, HTTPException, Optional, TwilioAdapter,_sanitize_value, datetime, db, now_iso, require_roles, sanitize_str, timedelta, timezone, uuid  # noqa: F401
from utils.phone import _normalize_phone
from fastapi import APIRouter
router = APIRouter()
# Auto-generated from routes.py section
# Section starts at line 1558

# ---------- DIGITAL SERVICE CARDS ----------

class ServiceCardPlanIn(BaseModel):
    name: str
    price: float
    services_per_year: int = 3
    duration_years: int = 1
    interval_months: int = 4
    interval_km: int = 0
    discount_pct: float = 0.0
    offer_note: str = ""
    active: bool = True


class ServiceCardCreate(BaseModel):
    plan_id: str
    customer_name: str
    customer_phone: str
    plate_number: Optional[str] = ""
    car_make: Optional[str] = ""
    car_model: Optional[str] = ""
    current_km: Optional[int] = 0
    notes: Optional[str] = ""
    discount_override: Optional[float] = None


@router.get("/service-card-plans")
async def list_sc_plans(user=Depends(require_roles("admin", "reception"))):
    return await db.service_card_plans.find({}, {"_id": 0}).to_list(100)


@router.post("/service-card-plans")
async def create_sc_plan(data: ServiceCardPlanIn, user=Depends(require_roles("admin"))):
    plan = {"id": str(uuid.uuid4()), **data.model_dump(), "created_at": now_iso(), "created_by": user["id"]}
    await db.service_card_plans.insert_one(plan)
    plan.pop("_id", None)
    return plan


@router.put("/service-card-plans/{plan_id}")
async def update_sc_plan(plan_id: str, data: dict, user=Depends(require_roles("admin"))):
    data.pop("id", None); data.pop("_id", None)
    await db.service_card_plans.update_one(
        {"id": plan_id},
        {"$set": {**_sanitize_value(data), "updated_at": now_iso()}}
    )
    return await db.service_card_plans.find_one({"id": plan_id}, {"_id": 0})


@router.get("/service-cards/check-customer/{phone}")
async def check_customer_card(phone: str, user=Depends(require_roles("admin", "reception"))):
    norm = _normalize_phone(phone)
    digits_only = "".join(c for c in phone if c.isdigit())
    raw_phone = digits_only[-10:] if len(digits_only) >= 10 else digits_only
    card = await db.service_cards.find_one(
        {"$or": [{"customer_phone": norm}, {"customer_phone": raw_phone}], "status": "active"}, {"_id": 0}
    )
    paid_count = await db.bookings.count_documents({"$or": [{"customer_phone": norm}, {"customer_phone": raw_phone}], "paid": True})
    return {
        "has_active_card": bool(card),
        "card": card,
        "paid_bookings_count": paid_count,
        "eligible_for_offer": paid_count >= 1 and not card,
        "is_new_customer": paid_count == 0,
    }


@router.get("/service-cards")
async def list_service_cards(user=Depends(require_roles("admin", "reception"))):
    return await db.service_cards.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)


@router.post("/service-cards")
async def create_service_card(data: ServiceCardCreate, user=Depends(require_roles("admin", "reception"))):
    plan = await db.service_card_plans.find_one({"id": data.plan_id}, {"_id": 0})
    if not plan:
        raise HTTPException(404, "Plan not found")
    if not plan.get("active"):
        raise HTTPException(400, "This plan is inactive")
    now_dt = datetime.now(timezone.utc)
    end_dt = now_dt + timedelta(days=365 * plan["duration_years"])
    discount = data.discount_override if data.discount_override is not None else plan["discount_pct"]
    total_slots = plan["services_per_year"] * plan["duration_years"]
    phone = _normalize_phone(data.customer_phone)
    card = {
        "id": str(uuid.uuid4()),
        "plan_id": data.plan_id,
        "plan_name": plan["name"],
        "customer_name": data.customer_name,
        "customer_phone": phone,
        "plate_number": (data.plate_number or "").upper(),
        "car_make": data.car_make or "",
        "car_model": data.car_model or "",
        "current_km": int(data.current_km or 0),
        "last_km": int(data.current_km or 0),
        "last_service_date": now_dt.isoformat(),
        "slots_total": total_slots,
        "slots_used": 0,
        "discount_pct": float(discount),
        "offer_note": plan.get("offer_note", ""),
        "interval_months": plan["interval_months"],
        "interval_km": plan["interval_km"],
        "price_paid": plan["price"],
        "start_date": now_dt.isoformat(),
        "end_date": end_dt.isoformat(),
        "status": "active",
        "notes": data.notes or "",
        "created_by": user["id"],
        "created_at": now_iso(),
    }
    await db.service_cards.insert_one(dict(card))
    card.pop("_id", None)
    if phone:
        sms_text = (
            f"MacJit: Your Digital Service Card '{plan['name']}' is now active!\n"
            f"Valid: {now_dt.strftime('%d %b %Y')} to {end_dt.strftime('%d %b %Y')}\n"
            f"Services: {total_slots} | Discount: {discount:.0f}% on every visit.\n"
        )
        if plan.get("offer_note"):
            sms_text += f"Offer: {plan['offer_note']}\n"
        sms_text += "Thank you for trusting MacJit Garage!"
        await TwilioAdapter.send_sms(phone, sms_text)
    return card


@router.get("/service-cards/{card_id}")
async def get_service_card(card_id: str, user=Depends(require_roles("admin", "reception"))):
    card = await db.service_cards.find_one({"id": card_id}, {"_id": 0})
    if not card:
        raise HTTPException(404, "Not found")
    return card


@router.put("/service-cards/{card_id}")
async def update_service_card(card_id: str, data: dict, user=Depends(require_roles("admin", "reception"))):
    data.pop("id", None); data.pop("_id", None)
    clean = _sanitize_value(data)
    clean["updated_at"] = now_iso()
    clean["updated_by"] = user["id"]
    await db.service_cards.update_one({"id": card_id}, {"$set": clean})
    return await db.service_cards.find_one({"id": card_id}, {"_id": 0})


@router.post("/service-cards/{card_id}/use-slot")
async def use_service_card_slot(card_id: str, data: Optional[dict] = None,
                                 user=Depends(require_roles("admin", "reception"))):
    card = await db.service_cards.find_one({"id": card_id})
    if not card:
        raise HTTPException(404, "Not found")
    if card.get("status") != "active":
        raise HTTPException(400, "Card is not active")
    if card["slots_used"] >= card["slots_total"]:
        raise HTTPException(400, "All service slots already used")
    current_km = int((data or {}).get("current_km") or card.get("current_km", 0))
    new_used = card["slots_used"] + 1
    upd: dict = {
        "slots_used": new_used,
        "last_service_date": now_iso(),
        "current_km": current_km,
        "last_km": current_km,
        "updated_at": now_iso(),
    }
    if new_used >= card["slots_total"]:
        upd["status"] = "exhausted"
    await db.service_cards.update_one({"id": card_id}, {"$set": upd})
    return await db.service_cards.find_one({"id": card_id}, {"_id": 0})


@router.post("/service-cards/send-reminders")
async def send_card_reminders(user=Depends(require_roles("admin", "reception"))):
    now_dt = datetime.now(timezone.utc)
    cards = await db.service_cards.find({"status": "active"}, {"_id": 0}).to_list(2000)
    sent = 0
    for card in cards:
        phone = card.get("customer_phone")
        if not phone:
            continue
        due = False
        last_svc = card.get("last_service_date")
        if last_svc:
            try:
                last_dt = datetime.fromisoformat(last_svc.replace("Z", "+00:00"))
                months_since = (now_dt - last_dt).days / 30.0
                if months_since >= card.get("interval_months", 4):
                    due = True
            except Exception:
                pass
        km_gap = card.get("interval_km", 0)
        if km_gap > 0:
            km_diff = card.get("current_km", 0) - card.get("last_km", 0)
            if km_diff >= km_gap:
                due = True
        if due:
            slots_left = card["slots_total"] - card["slots_used"]
            msg = (
                f"MacJit Reminder: Hi {card['customer_name']}, your {card['plan_name']} service is due!\n"
                f"Vehicle: {card.get('plate_number') or card.get('car_make', '')}\n"
                f"Services remaining: {slots_left} | Discount: {card['discount_pct']:.0f}%\n"
                f"Book now at MacJit Garage."
            )
            await TwilioAdapter.send_sms(phone, msg)
            sent += 1
    return {"ok": True, "reminders_sent": sent}


@router.post("/service-cards/remind-custom")
async def remind_custom(data: dict, user=Depends(require_roles("admin", "reception"))):
    """Send a one-off SMS reminder to any phone (even without a card)."""
    phone = sanitize_str(data.get("phone"))
    message = sanitize_str(data.get("message"), max_len=300)
    name = sanitize_str(data.get("name", "Customer"), max_len=100)
    if not phone or not message:
        raise HTTPException(400, "phone and message are required")
    await TwilioAdapter.send_sms(_normalize_phone(phone), message)
    return {"ok": True}


