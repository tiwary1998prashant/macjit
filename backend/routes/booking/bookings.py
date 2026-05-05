from server import ApprovalReq, AssignIn, BaseModel, BookingCreate, Depends, HTTPException, ItemAdd, List, Optional, RazorpayAdapter, Request, TwilioAdapter, _gen_otp, _rate_check, _store_otp, _verify_otp, auto_assign_booking, datetime, db, encrypt_field, get_current_user, get_recipients_for_booking, json, logger, now_iso, os, public_booking, public_bookings, publish_event, require_roles, timedelta, timezone, uuid  # noqa: F401
from fastapi import APIRouter
router = APIRouter()
from constants import DEFAULT_PRICES, LOYALTY_DISCOUNT
# Auto-generated from routes.py section
# Section starts at line 104
from utils.phone import _normalize_phone


ACTIVE_BOOKING_STATUSES = {"BOOKED", "ASSIGNED", "IN_SERVICE", "READY_TO_TEST", "QA_DONE", "BILLED"}


def _today_bounds():
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat(), (start + timedelta(days=1)).isoformat()


async def _ensure_one_booking_per_day(phone: str, plate_number: str):
    start, end = _today_bounds()
    existing = await db.bookings.find_one({
        "customer_phone": phone,
        "plate_number": (plate_number or "").strip().upper(),
        "created_at": {"$gte": start, "$lt": end},
        "status": {"$in": list(ACTIVE_BOOKING_STATUSES)},
    }, {"_id": 0})
    if existing:
        raise HTTPException(409, "This phone number already has this bike booked today.")

# ---------- BAYS ----------
@router.get("/bays")
async def list_bays(user=Depends(get_current_user)):
    return await db.bays.find({}, {"_id": 0}).to_list(100)


# ---------- BOOKINGS ----------
@router.post("/bookings")
async def create_booking(data: BookingCreate, user=Depends(require_roles("reception", "admin"))):
    """Walk-in booking. Customers do NOT log in — we just keep their name/phone on the booking
    and they track everything via the public /track page using the vehicle plate number."""
    if not (data.customer_phone and data.customer_name):
        raise HTTPException(400, "customer_name and customer_phone are required")
    customer_phone = _normalize_phone(data.customer_phone)
    plate_number = (data.plate_number or "").strip().upper()
    await _ensure_one_booking_per_day(customer_phone, plate_number)
    # Look up loyalty info from prior bookings (no user account needed)
    prior = await db.bookings.aggregate([
        {"$match": {"customer_phone": customer_phone, "paid": True}},
        {"$group": {"_id": None, "total": {"$sum": "$bill_amount"}}}
    ]).to_list(1)
    total_spent = (prior[0]["total"] if prior else 0)
    tier = "GOLD" if total_spent >= 25000 else ("SILVER" if total_spent >= 10000 else "BRONZE")
    customer = {
        "id": f"walkin-{customer_phone}",
        "name": data.customer_name,
        "phone": customer_phone,
        "loyalty_tier": tier,
        "total_spent": total_spent,
    }
    booking = {
        "id": str(uuid.uuid4()),
        "customer_id": customer["id"],
        "customer_name": encrypt_field(customer["name"]),
        "customer_name_plain": customer["name"],
        "customer_phone": customer["phone"],
        "loyalty_tier": tier,
        "car_make": data.car_make,
        "car_model": data.car_model,
        "plate_number": plate_number,
        "service_type": data.service_type,
        "notes": data.notes,
        "status": "BOOKED",
        "mechanic_id": None,
        "mechanic_name": None,
        "bay_id": None,
        "bay_name": None,
        "items": [],
        "approval_pending": False,
        "approval_reason": None,
        "extra_cost": 0.0,
        "stream_active": False,
        "bill_amount": 0.0,
        "payment_link": None,
        "paid": False,
        "auto_assigned": False,
        "estimated_start_at": None,
        "estimated_end_at": None,
        "created_at": now_iso(),
        "started_at": None,
        "finished_at": None,
        "qa_done_at": None,
        "billed_at": None,
        "paid_at": None,
    }
    await db.bookings.insert_one(dict(booking))
    booking.pop("_id", None)
    # Auto-assign mechanic + bay (1h45m slot, 8am–6pm). No manual reception step.
    assigned = await auto_assign_booking(booking["id"])
    if assigned:
        booking = assigned
        recipients = await get_recipients_for_booking(booking)
        await publish_event("BOOKING_CREATED", booking, recipients,
                            extra={"auto_assigned_to": booking.get("mechanic_name"),
                                   "estimated_start_at": booking.get("estimated_start_at"),
                                   "estimated_end_at": booking.get("estimated_end_at")})
        await publish_event("BOOKING_ASSIGNED", booking, recipients)
    else:
        recipients = await get_recipients_for_booking(booking)
        await publish_event("BOOKING_CREATED", booking, recipients)
    return public_booking(booking)


@router.get("/bookings")
async def list_bookings(status: Optional[str] = None, user=Depends(get_current_user)):
    q = {}
    if status:
        q["status"] = status
    if user["role"] == "mechanic":
        q["mechanic_id"] = user["id"]
    elif user["role"] == "tester":
        q["status"] = {"$in": ["READY_TO_TEST", "QA_DONE", "BILLED", "PAID"]}
    bookings = await db.bookings.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)
    return public_bookings(bookings)


@router.get("/bookings/{booking_id}")
async def get_booking(booking_id: str, user=Depends(get_current_user)):
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    return public_booking(b)


@router.post("/bookings/{booking_id}/auto-assign")
async def reassign(booking_id: str, user=Depends(require_roles("reception", "admin"))):
    b = await auto_assign_booking(booking_id)
    if not b:
        raise HTTPException(400, "No mechanics or bays available")
    recipients = await get_recipients_for_booking(b)
    await publish_event("BOOKING_ASSIGNED", b, recipients)
    return public_booking(b)


@router.patch("/bookings/{booking_id}/assign")
async def assign(booking_id: str, data: AssignIn, user=Depends(require_roles("reception", "admin"))):
    mech = await db.users.find_one({"id": data.mechanic_id, "role": "mechanic"})
    bay = await db.bays.find_one({"id": data.bay_id})
    if not mech or not bay:
        raise HTTPException(404, "Mechanic or bay not found")
    upd = {"mechanic_id": mech["id"], "mechanic_name": mech["name"],
           "mechanic_phone": mech.get("phone"),
           "bay_id": bay["id"], "bay_name": bay["name"],
           "status": "ASSIGNED"}
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    recipients = await get_recipients_for_booking(b)
    await publish_event("BOOKING_ASSIGNED", b, recipients)
    return public_booking(b)


@router.post("/bookings/{booking_id}/start")
async def start_service(booking_id: str, user=Depends(require_roles("mechanic"))):
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b or b.get("mechanic_id") != user["id"]:
        raise HTTPException(403, "Not your car")
    upd = {"status": "IN_SERVICE", "stream_active": True, "started_at": now_iso()}
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    b.update(upd)
    recipients = await get_recipients_for_booking(b, include_admin=False)  # spec: not admin
    await publish_event("SERVICE_STARTED", b, recipients)
    return public_booking(b)


@router.post("/bookings/{booking_id}/items")
async def add_item(booking_id: str, data: ItemAdd, user=Depends(require_roles("mechanic"))):
    inv = await db.inventory.find_one({"id": data.inventory_id})
    if not inv:
        raise HTTPException(404, "Item not found")
    if inv["stock"] < data.qty:
        raise HTTPException(400, "Insufficient stock")
    line = {"inventory_id": inv["id"], "name": inv["name"], "sku": inv["sku"],
            "qty": data.qty, "price": inv["price"], "subtotal": inv["price"] * data.qty}
    await db.bookings.update_one({"id": booking_id}, {"$push": {"items": line}})
    await db.inventory.update_one({"id": inv["id"]}, {"$inc": {"stock": -data.qty}})
    return public_booking(await db.bookings.find_one({"id": booking_id}, {"_id": 0}))


@router.delete("/bookings/{booking_id}/items/{inventory_id}")
async def remove_item(booking_id: str, inventory_id: str, user=Depends(require_roles("mechanic"))):
    b = await db.bookings.find_one({"id": booking_id})
    if not b:
        raise HTTPException(404, "Not found")
    item = next((i for i in b.get("items", []) if i["inventory_id"] == inventory_id), None)
    if item:
        await db.inventory.update_one({"id": inventory_id}, {"$inc": {"stock": item["qty"]}})
    await db.bookings.update_one({"id": booking_id}, {"$pull": {"items": {"inventory_id": inventory_id}}})
    return public_booking(await db.bookings.find_one({"id": booking_id}, {"_id": 0}))


@router.post("/bookings/{booking_id}/request-approval")
async def request_approval(booking_id: str, data: ApprovalReq, user=Depends(require_roles("mechanic"))):
    upd = {"approval_pending": True, "approval_reason": data.reason, "extra_cost": data.extra_cost}
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    # Generate OTP and send via SMS to customer for secure approval
    cust_phone = b.get("customer_phone")
    if cust_phone:
        otp = _gen_otp()
        _store_otp(booking_id, otp, cust_phone)
        otp_msg = (
            f"MacJit OTP: {otp}\n"
            f"Your mechanic needs approval for extra work on {b.get('plate_number','your car')}.\n"
            f"Extra cost: \u20B9{data.extra_cost}. Reason: {data.reason}\n"
            f"Enter this OTP on the tracking page to approve. Valid 10 minutes. Do NOT share."
        )
        await TwilioAdapter.send_sms(cust_phone, otp_msg)
    recipients = await get_recipients_for_booking(b)
    await publish_event("APPROVAL_REQUESTED", b, recipients, extra={"reason": data.reason, "extra_cost": data.extra_cost})
    return public_booking(b)


@router.post("/bookings/{booking_id}/approval-otp/resend")
async def resend_approval_otp(booking_id: str, request: Request):
    """Public: resend approval OTP to the customer. Rate-limited per booking."""
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(f"otp_resend:{booking_id}:{ip}", limit=3, window_sec=300):
        raise HTTPException(429, "Too many OTP requests — try again in 5 minutes")
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    if not b.get("approval_pending"):
        raise HTTPException(400, "No approval pending for this booking")
    cust_phone = b.get("customer_phone")
    if not cust_phone:
        raise HTTPException(400, "No phone on file for this booking")
    otp = _gen_otp()
    _store_otp(booking_id, otp, cust_phone)
    otp_msg = (
        f"MacJit OTP: {otp}\n"
        f"Approve extra work on {b.get('plate_number','your car')}. Valid 10 minutes. Do NOT share."
    )
    await TwilioAdapter.send_sms(cust_phone, otp_msg)
    return {"ok": True, "sent_to": cust_phone[-4:].rjust(10, "*")}


@router.post("/bookings/{booking_id}/approve")
async def approve(booking_id: str, data: Optional[dict] = None, request: Request = None):
    """Public approval — customer must supply the OTP sent to their phone via SMS."""
    ip = (request.client.host if request and request.client else "unknown")
    if not _rate_check(f"otp_verify:{booking_id}:{ip}", limit=5, window_sec=300):
        raise HTTPException(429, "Too many attempts — try again in 5 minutes")
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    otp = str((data or {}).get("otp") or "").strip()
    if not otp:
        raise HTTPException(400, "OTP is required")
    if not _verify_otp(booking_id, otp):
        raise HTTPException(403, "Invalid or expired OTP — request a new one")
    await db.bookings.update_one({"id": booking_id}, {"$set": {"approval_pending": False}})
    b["approval_pending"] = False
    recipients = await get_recipients_for_booking(b)
    await publish_event("APPROVAL_GRANTED", b, recipients)
    return public_booking(b)


@router.post("/bookings/{booking_id}/finish")
async def finish(booking_id: str, user=Depends(require_roles("mechanic"))):
    upd = {"status": "READY_TO_TEST", "stream_active": False, "finished_at": now_iso()}
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    recipients = await get_recipients_for_booking(b, include_tester=True)
    await publish_event("SERVICE_FINISHED", b, recipients)
    # Auto-pick the next ASSIGNED booking for this mechanic, ordered by ETA
    nxt = await db.bookings.find_one(
        {"mechanic_id": user["id"], "status": "ASSIGNED"},
        {"_id": 0},
        sort=[("estimated_start_at", 1)],
    )
    return {**b, "next_booking_id": nxt["id"] if nxt else None,
            "next_booking_plate": nxt["plate_number"] if nxt else None}


@router.post("/bookings/{booking_id}/qa-done")
async def qa_done(booking_id: str, user=Depends(require_roles("tester"))):
    upd = {"status": "QA_DONE", "qa_done_at": now_iso(),
           "tester_id": user["id"], "tester_name": user["name"],
           "tester_phone": user.get("phone"),
           "qa_fail_reasons": [],
           "qa_fail_notes": "",
           "qa_failed_at": None,
           "qa_fail_tester_id": None,
           "qa_fail_tester_name": None}
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    recipients = await get_recipients_for_booking(b, include_tester=True)
    await publish_event("QA_DONE", b, recipients)
    return public_booking(b)


class QAFailIn(BaseModel):
    reasons: List[str]
    notes: Optional[str] = None


@router.post("/bookings/{booking_id}/qa-fail")
async def qa_fail(booking_id: str, body: QAFailIn, user=Depends(require_roles("tester"))):
    if not body.reasons:
        raise HTTPException(400, "At least one fail reason is required")
    upd = {
        "status": "IN_SERVICE",
        "qa_fail_reasons": body.reasons,
        "qa_fail_notes": body.notes or "",
        "qa_failed_at": now_iso(),
        "qa_fail_tester_id": user["id"],
        "qa_fail_tester_name": user["name"],
    }
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    # Notify mechanic via in-app + SMS (not customer)
    recipients = await get_recipients_for_booking(b, include_tester=True, include_reception=True)
    await publish_event("QA_FAIL", b, recipients, extra={
        "reasons": body.reasons,
        "notes": body.notes or "",
        "customer_name": b.get("customer_name_plain") or b.get("customer_name"),
        "customer_phone": b.get("customer_phone"),
        "mechanic_id": b.get("mechanic_id"),
        "mechanic_name": b.get("mechanic_name"),
        "bay_name": b.get("bay_name"),
    })
    mechanic_phone = b.get("mechanic_phone") or ""
    if mechanic_phone:
        reasons_str = ", ".join(body.reasons)
        msg = (f"MacJit QA FAILED: {b.get('plate_number')} ({b.get('car_make','')} {b.get('car_model','')})\n"
               f"Customer: {b.get('customer_name_plain') or b.get('customer_name','')} {b.get('customer_phone','')}\n"
               f"Reason(s): {reasons_str}\n"
               f"Please fix and resubmit for QA.")
        if body.notes:
            msg += f"\nNotes: {body.notes}"
        await TwilioAdapter.send_sms(mechanic_phone, msg)
    return public_booking(b)


def _calculate_bill(b: dict, pricing: Optional[dict], cust: Optional[dict],
                    extra_discount: float = 0.0):
    base_charge = (pricing or {}).get("base_price") or DEFAULT_PRICES.get(b.get("service_type", "general"), 800)  # pricing from services DB
    items_total = sum(i.get("subtotal", 0) for i in b.get("items", []))
    extra_cost = b.get("extra_cost", 0) or 0
    subtotal = base_charge + items_total + extra_cost
    tier = (cust or {}).get("loyalty_tier", "BRONZE")
    discount_pct = LOYALTY_DISCOUNT.get(tier, 0)
    loyalty_discount = round(subtotal * discount_pct / 100)
    extra_discount = max(0.0, float(extra_discount or 0))
    total_discount = loyalty_discount + extra_discount
    bill_amount = max(0, subtotal - total_discount)
    return {
        "base_charge": base_charge,
        "items_total": items_total,
        "extra_cost": extra_cost,
        "subtotal": subtotal,
        "loyalty_tier": tier,
        "discount_pct": discount_pct,
        "loyalty_discount": loyalty_discount,
        "extra_discount": extra_discount,
        "discount": total_discount,
        "bill_amount": bill_amount,
    }


@router.get("/bookings/{booking_id}/bill-preview")
async def bill_preview(booking_id: str, extra_discount: float = 0.0,
                       user=Depends(require_roles("reception", "admin"))):
    """Soft-copy preview for reception. Does NOT change booking status."""
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    pricing = await db.services.find_one({"key": b.get("service_type")}, {"_id": 0})
    cust = {"name": b.get("customer_name"), "phone": b.get("customer_phone"),
            "loyalty_tier": b.get("loyalty_tier", "BRONZE")}
    calc = _calculate_bill(b, pricing, cust, extra_discount=extra_discount)
    return {
        "booking_id": booking_id,
        "customer": {"name": cust["name"], "phone": cust["phone"]},
        "car": {"make": b.get("car_make"), "model": b.get("car_model"), "plate": b.get("plate_number")},
        "service_type": b.get("service_type"),
        "items": b.get("items", []),
        "approval_reason": b.get("approval_reason"),
        **calc,
        "is_draft": True,
    }

@router.post("/bookings/{booking_id}/bill")
async def bill(booking_id: str, data: Optional[dict] = None,
               user=Depends(require_roles("reception", "admin"))):

    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")

    # ✅ Get pricing
    pricing = await db.services.find_one(
        {"key": b.get("service_type")},
        {"_id": 0}
    )

    # ✅ Calculate bill
    calc = _calculate_bill(
        b,
        pricing,
        {"loyalty_tier": b.get("loyalty_tier", "BRONZE")}
    )

    bill_amount = calc["bill_amount"]

    try:
        link, rzp_id = await RazorpayAdapter.create_payment_link_full(
            bill_amount,
            booking_id,
            b.get("customer_phone"),
            notes={"booking_id": booking_id}
        )
    except Exception as e:
        raise HTTPException(500, f"Payment failed: {str(e)}")

    await db.bookings.update_one(
        {"id": booking_id},
        {"$set": {
            **calc,
            "payment_link": link,
            "rzp_payment_link_id": rzp_id,
            "status": "BILLED",
            "billed_at": now_iso()
        }}
    )

    return {
        "payment_link": link,
        "status": "BILLED",
        "amount": bill_amount,
        **calc,
    }
               



@router.post("/razorpay/webhook")
async def razorpay_webhook(request: Request):
    """Razorpay webhook receiver. Verifies the X-Razorpay-Signature header against
    RAZORPAY_WEBHOOK_SECRET and, on a payment.captured event, marks the matching
    booking as paid. This catches payments made via the SMS/WhatsApp pay link
    (i.e. payments that don't go through the in-app Checkout modal)."""
    import hmac, hashlib
    secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    if not secret:
        raise HTTPException(503, "Webhook secret not configured")
    raw = await request.body()
    signature = request.headers.get("x-razorpay-signature", "")
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        logger.warning("[RAZORPAY-WEBHOOK] bad signature")
        raise HTTPException(400, "Invalid signature")
    try:
        payload = json.loads(raw.decode() or "{}")
    except Exception:
        raise HTTPException(400, "Bad JSON")
    event = payload.get("event", "")
    if event not in ("payment.captured", "payment_link.paid", "order.paid"):
        return {"ok": True, "ignored": event}
    payment = (((payload.get("payload") or {}).get("payment") or {}).get("entity") or {})
    notes = payment.get("notes") or {}
    booking_id = notes.get("booking_id")
    # payment_link events carry booking_id in the payment_link entity notes
    if not booking_id:
        plink = (((payload.get("payload") or {}).get("payment_link") or {}).get("entity") or {})
        booking_id = (plink.get("notes") or {}).get("booking_id")
    if not booking_id:
        logger.warning(f"[RAZORPAY-WEBHOOK] no booking_id in notes for event={event}")
        return {"ok": True, "no_booking": True}
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        return {"ok": True, "not_found": True}
    if b.get("paid"):
        return {"ok": True, "already_paid": True}
    upd = {
        "status": "PAID", "paid": True, "paid_at": now_iso(),
        "razorpay_payment_id": payment.get("id"),
        "razorpay_order_id": payment.get("order_id"),
        "payment_method": "razorpay",
    }
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    cust_phone = b.get("customer_phone")
    if cust_phone:
        public_url = os.environ.get("PUBLIC_URL") or os.environ.get("APP_URL") or ""
        invoice_url = f"{public_url}/api/invoices/{booking_id}.pdf"
        msg = (
            f"MacJit Invoice — {b.get('plate_number','')}\n"
            f"Total Paid: \u20B9{b.get('bill_amount',0)}\n"
            f"Invoice: {invoice_url}\n"
            f"Thanks for choosing MacJit. Drive safe!"
        )
        await TwilioAdapter.send_whatsapp(cust_phone, msg)
        sms_invoice = f"MacJit: Payment of \u20B9{b.get('bill_amount',0)} received for {b.get('plate_number','')}. Invoice: {invoice_url}"
        await TwilioAdapter.send_sms(cust_phone, sms_invoice)
    recipients = await get_recipients_for_booking(b)
    await publish_event("PAID", b, recipients)
    return {"ok": True, "booking_id": booking_id}


@router.post("/bookings/{booking_id}/razorpay/order")
async def create_razorpay_order(booking_id: str, data: Optional[dict] = None):
    """Create a Razorpay Order for a booking. Customer must supply plate to confirm.
    Returns the order_id + key_id needed by the Razorpay Checkout JS modal."""
    if not (os.environ.get("RAZORPAY_KEY_ID") and os.environ.get("RAZORPAY_KEY_SECRET")):
        raise HTTPException(503, "Online payment is not configured")
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    plate = ((data or {}).get("plate_number") or "").strip().upper()
    if not plate or plate != (b.get("plate_number") or "").upper():
        raise HTTPException(403, "Plate number does not match this booking")
    if b.get("paid"):
        raise HTTPException(400, "Booking is already paid")
    amount_paise = int(round(float(b.get("bill_amount") or 0) * 100))
    if amount_paise <= 0:
        raise HTTPException(400, "Bill not generated yet")
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15) as cli:
            r = await cli.post(
                "https://api.razorpay.com/v1/orders",
                json={
                    "amount": amount_paise,
                    "currency": "INR",
                    "receipt": booking_id[:40],
                    "notes": {"booking_id": booking_id, "plate": b.get("plate_number", "")},
                },
                auth=(os.environ["RAZORPAY_KEY_ID"], os.environ["RAZORPAY_KEY_SECRET"]),
            )
            if r.status_code >= 400:
                logger.error(f"[RAZORPAY-ORDER-ERR] {r.status_code} {r.text}")
                raise HTTPException(502, "Razorpay order creation failed")
            order = r.json()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[RAZORPAY-ORDER-EXC] {e}")
        raise HTTPException(502, "Razorpay unavailable")
    return {
        "order_id": order["id"],
        "amount": order["amount"],
        "currency": order["currency"],
        "key_id": os.environ["RAZORPAY_KEY_ID"],
        "name": "MacJit Garage",
        "description": f"Service for {b.get('plate_number', '')}",
        "prefill": {
            "name": b.get("customer_name") or "",
            "contact": b.get("customer_phone") or "",
            "email": b.get("customer_email") or "",
        },
    }


@router.post("/bookings/{booking_id}/razorpay/verify")
async def verify_razorpay_payment(booking_id: str, data: dict):
    """Verify a Razorpay payment signature (HMAC-SHA256 of order_id|payment_id with
    key_secret). Only on success do we mark the booking as paid."""
    import hmac, hashlib
    payment_id = (data.get("razorpay_payment_id") or "").strip()
    order_id = (data.get("razorpay_order_id") or "").strip()
    signature = (data.get("razorpay_signature") or "").strip()
    plate = (data.get("plate_number") or "").strip().upper()
    if not (payment_id and order_id and signature):
        raise HTTPException(400, "Missing Razorpay payment fields")
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    if not plate or plate != (b.get("plate_number") or "").upper():
        raise HTTPException(403, "Plate number does not match this booking")
    secret = (os.environ.get("RAZORPAY_KEY_SECRET") or "").encode()
    expected = hmac.new(secret, f"{order_id}|{payment_id}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        logger.warning(f"[RAZORPAY-VERIFY-FAIL] booking={booking_id}")
        raise HTTPException(400, "Invalid payment signature")
    upd = {
        "status": "PAID", "paid": True, "paid_at": now_iso(),
        "razorpay_payment_id": payment_id, "razorpay_order_id": order_id,
        "payment_method": "razorpay",
    }
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    cust_phone = b.get("customer_phone")
    if cust_phone:
        public_url = os.environ.get("PUBLIC_URL") or os.environ.get("APP_URL") or ""
        invoice_url = f"{public_url}/api/invoices/{booking_id}.pdf"
        items_summary = ", ".join([f"{i['name']} x{i['qty']}" for i in (b.get("items") or [])][:3]) or "Service"
        msg = (
            f"MacJit Invoice — {b.get('plate_number','')}\n"
            f"Service: {b.get('service_type','')}\n"
            f"Items: {items_summary}\n"
            f"Total Paid: \u20B9{b.get('bill_amount',0)}\n"
            f"Invoice: {invoice_url}\n"
            f"Thanks for choosing MacJit. Drive safe!"
        )
        await TwilioAdapter.send_whatsapp(cust_phone, msg)
        sms_invoice = f"MacJit: Payment of \u20B9{b.get('bill_amount',0)} received for {b.get('plate_number','')}. Invoice: {invoice_url}"
        await TwilioAdapter.send_sms(cust_phone, sms_invoice)
    recipients = await get_recipients_for_booking(b)
    await publish_event("PAID", b, recipients)
    return public_booking(b)


@router.post("/bookings/{booking_id}/pay")
async def pay(booking_id: str, data: Optional[dict] = None):
    """Public pay confirmation. Customer must include their plate to confirm (when calling
    from the public /track page). Reception/admin can also call this."""
    b0 = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b0:
        raise HTTPException(404, "Not found")
    plate_supplied = ((data or {}).get("plate_number") or "").strip().upper()
    if plate_supplied and plate_supplied != (b0.get("plate_number") or "").upper():
        raise HTTPException(403, "Plate number does not match this booking")
    upd = {"status": "PAID", "paid": True, "paid_at": now_iso()}
    await db.bookings.update_one({"id": booking_id}, {"$set": upd})
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    # Send invoice link to customer via WhatsApp + SMS
    cust_phone = b.get("customer_phone")
    if cust_phone:
        public_url = os.environ.get("PUBLIC_URL") or os.environ.get("APP_URL") or ""
        invoice_url = f"{public_url}/api/invoices/{booking_id}.pdf"
        items_summary = ", ".join([f"{i['name']} x{i['qty']}" for i in (b.get("items") or [])][:3]) or "Service"
        msg = (
            f"MacJit Invoice — {b.get('plate_number','')}\n"
            f"Service: {b.get('service_type','')}\n"
            f"Items: {items_summary}\n"
            f"Total Paid: \u20B9{b.get('bill_amount',0)}\n"
            f"Invoice: {invoice_url}\n"
            f"Thanks for choosing MacJit. Drive safe!"
        )
        await TwilioAdapter.send_whatsapp(cust_phone, msg)
        sms_invoice = f"MacJit: Payment received for {b.get('plate_number','')}. \u20B9{b.get('bill_amount',0)} paid. Invoice: {invoice_url}"
        await TwilioAdapter.send_sms(cust_phone, sms_invoice)
    recipients = await get_recipients_for_booking(b)
    await publish_event("PAID", b, recipients)
    return public_booking(b)


