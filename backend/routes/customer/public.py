from datetime import datetime, timezone, timedelta

from pydantic import BaseModel
from server import HTTPException, Optional, TwilioAdapter, db, encrypt_field, get_recipients_for_booking, now_iso, os, public_booking, public_bookings, public_customer_name, publish_event, uuid  # noqa: F401
from utils.phone import _normalize_phone

from fastapi import APIRouter
router = APIRouter()
# Auto-generated from routes.py section
# Section starts at line 703

ACTIVE_PUBLIC_STATUSES = {"BOOKED", "ASSIGNED", "IN_SERVICE", "READY_TO_TEST", "QA_DONE", "BILLED"}


class CustomerBookingIn(BaseModel):
    customer_name: str
    customer_phone: str
    plate_number: str
    car_make: str = "Bike"
    car_model: str = ""
    service_type: str = "general"
    problem: str = ""
    preferred_slot: Optional[str] = None


def _plate(value: str) -> str:
    return (value or "").strip().upper().replace(" ", "-")


def _today_bounds():
    now = datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat(), (start + timedelta(days=1)).isoformat()


def _parse_slot(value: Optional[str]) -> datetime:
    now = datetime.now(timezone.utc)
    if value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    slot = now + timedelta(hours=2)
    if slot.hour < 8:
        slot = slot.replace(hour=10, minute=0, second=0, microsecond=0)
    elif slot.hour >= 17:
        slot = (slot + timedelta(days=1)).replace(hour=10, minute=0, second=0, microsecond=0)
    return slot.replace(minute=0, second=0, microsecond=0)


async def _cancel_expired_pre_arrivals():
    now = now_iso()
    expired = await db.bookings.find({
        "status": "BOOKED",
        "garage_presence_status": "NOT_IN_GARAGE",
        "drop_deadline_at": {"$lt": now},
    }, {"_id": 0}).to_list(100)
    for b in expired:
        await db.bookings.update_one(
            {"id": b["id"], "status": "BOOKED"},
            {"$set": {"status": "CANCELLED", "cancelled_at": now, "cancel_reason": "Vehicle not dropped before slot time"}}
        )


async def _ensure_one_booking_per_day(phone: str, plate_number: str):
    start, end = _today_bounds()
    existing = await db.bookings.find_one({
        "customer_phone": phone,
        "plate_number": plate_number,
        "created_at": {"$gte": start, "$lt": end},
        "status": {"$in": list(ACTIVE_PUBLIC_STATUSES)},
    }, {"_id": 0})
    if existing:
        raise HTTPException(
            409,
            "This phone number already has this bike booked today. Track it instead of creating another booking."
        )


async def _make_public_booking(data: CustomerBookingIn, source: str = "chatbot", reopened_from: str = ""):
    phone = _normalize_phone(data.customer_phone)
    plate_number = _plate(data.plate_number)
    if not data.customer_name.strip():
        raise HTTPException(400, "Customer name required")
    if len("".join(ch for ch in phone if ch.isdigit())) < 10:
        raise HTTPException(400, "Valid phone required")
    if not plate_number:
        raise HTTPException(400, "Bike number required")
    await _ensure_one_booking_per_day(phone, plate_number)

    slot = _parse_slot(data.preferred_slot)
    booking = {
        "id": str(uuid.uuid4()),
        "customer_id": f"walkin-{phone}",
        "customer_name": encrypt_field(data.customer_name.strip()),
        "customer_name_plain": data.customer_name.strip(),
        "customer_phone": phone,
        "loyalty_tier": "BRONZE",
        "car_make": data.car_make.strip() or "Bike",
        "car_model": data.car_model.strip() or "Bike",
        "plate_number": plate_number,
        "service_type": data.service_type or "general",
        "notes": data.problem or "",
        "status": "BOOKED",
        "garage_presence_status": "NOT_IN_GARAGE",
        "source": source,
        "reopened_from": reopened_from or None,
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
        "estimated_start_at": slot.isoformat(),
        "estimated_end_at": (slot + timedelta(hours=2)).isoformat(),
        "drop_deadline_at": slot.isoformat(),
        "created_at": now_iso(),
        "started_at": None,
        "finished_at": None,
        "qa_done_at": None,
        "billed_at": None,
        "paid_at": None,
    }
    await db.bookings.insert_one(dict(booking))
    booking.pop("_id", None)
    recipients = await get_recipients_for_booking(booking, include_mechanic=False)
    await publish_event("BOOKING_CREATED", booking, recipients, extra={"source": source})
    track_url = f"{os.environ.get('PUBLIC_URL') or os.environ.get('APP_URL') or ''}/track?plate={plate_number}"
    try:
        await TwilioAdapter.send_sms(
            phone,
            f"MacJit: Booking confirmed for {plate_number}. Drop your bike on or before "
            f"{slot.strftime('%d %b, %I:%M %p')}. If it is not dropped by then, booking auto-cancels. Track: {track_url}"
        )
    except Exception:
        pass
    return {"booking": public_booking(booking), "track_url": track_url}


@router.post("/public/bookings")
async def create_public_booking(data: CustomerBookingIn):
    return await _make_public_booking(data)

# ---------- Public customer tracking (no auth) ----------
@router.get("/track")
async def track_by_plate(plate: str):
    """Public endpoint: customer enters their plate number and sees the latest booking,
    bill (if generated) and a pay action — no login required."""
    await _cancel_expired_pre_arrivals()
    plate_q = _plate(plate)
    if not plate_q:
        raise HTTPException(400, "Plate number required")
    # Case-insensitive match. Use regex anchored to avoid partial collisions.
    import re
    bookings = await db.bookings.find(
        {"plate_number": {"$regex": f"^{re.escape(plate_q)}$", "$options": "i"}},
        {"_id": 0}
    ).sort("created_at", -1).to_list(20)
    if not bookings:
        raise HTTPException(404, "No booking found for this vehicle number")
    active = next((b for b in bookings if b.get("status") not in ("PAID", "CANCELLED")), bookings[0])
    public_url = os.environ.get("PUBLIC_URL") or os.environ.get("APP_URL") or ""
    invoice_url = (f"{public_url}/api/invoices/{active['id']}.pdf"
                   if active.get("status") in ("BILLED", "PAID") else None)
    return {"active": public_booking(active), "history": public_bookings(bookings), "invoice_url": invoice_url}


@router.post("/track/{booking_id}/reopen")
async def reopen_recent_service(booking_id: str, data: Optional[dict] = None):
    """Public: reopen a paid/finished service within 7 days for follow-up work."""
    original = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not original:
        raise HTTPException(404, "Not found")
    plate = _plate((data or {}).get("plate_number"))
    phone = _normalize_phone((data or {}).get("customer_phone") or original.get("customer_phone"))
    if plate != _plate(original.get("plate_number")):
        raise HTTPException(403, "Plate number does not match this booking")
    completed_at = original.get("paid_at") or original.get("qa_done_at") or original.get("finished_at") or original.get("created_at")
    try:
        completed_dt = datetime.fromisoformat(completed_at)
    except Exception:
        completed_dt = datetime.now(timezone.utc) - timedelta(days=30)
    if datetime.now(timezone.utc) - completed_dt > timedelta(days=7):
        raise HTTPException(400, "Reopen window expired. Please create a new booking.")
    payload = CustomerBookingIn(
        customer_name=public_customer_name(original) or "Customer",
        customer_phone=phone,
        plate_number=original.get("plate_number"),
        car_make=original.get("car_make") or "Bike",
        car_model=original.get("car_model") or "",
        service_type=original.get("service_type") or "general",
        problem=(data or {}).get("problem") or "Follow-up visit within 7 days",
        preferred_slot=(data or {}).get("preferred_slot"),
    )
    return await _make_public_booking(payload, source="reopen", reopened_from=booking_id)


@router.get("/track/booking/{booking_id}")
async def track_booking_by_id(booking_id: str, plate: str = ""):
    """Public: fetch a single booking by id, but only if the supplied plate matches.
    Used by the customer-side checkout page so the customer can see their bill
    without logging in."""
    plate_q = (plate or "").strip().upper()
    if not plate_q:
        raise HTTPException(400, "Plate number required")
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    if (b.get("plate_number") or "").upper() != plate_q:
        raise HTTPException(403, "Plate number does not match this booking")
    return public_booking(b)


@router.post("/track/{booking_id}/send-bill")
async def send_bill_whatsapp(booking_id: str, data: Optional[dict] = None):
    """Public: re-send the current bill summary to the customer's WhatsApp.
    Plate number must be supplied to confirm identity."""
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    plate = ((data or {}).get("plate_number") or "").strip().upper()
    if not plate or plate != (b.get("plate_number") or "").upper():
        raise HTTPException(403, "Plate number does not match this booking")
    if b.get("status") not in ("BILLED", "PAID"):
        raise HTTPException(400, "Bill not generated yet — service still in progress.")
    cust_phone = b.get("customer_phone")
    if not cust_phone:
        raise HTTPException(400, "No phone on file")
    public_url = os.environ.get("PUBLIC_URL") or os.environ.get("APP_URL") or ""
    invoice_url = f"{public_url}/api/invoices/{booking_id}.pdf"
    pay_link = b.get("payment_link") or f"{public_url}/track?plate={b.get('plate_number','')}"
    items_summary = ", ".join([f"{i['name']} x{i['qty']}" for i in (b.get("items") or [])][:3]) or "Service"
    status_word = "PAID" if b.get("paid") else "DUE"
    msg = (
        f"MacJit Bill — {b.get('plate_number','')}\n"
        f"Service: {b.get('service_type','')}\n"
        f"Items: {items_summary}\n"
        f"Amount {status_word}: \u20B9{b.get('bill_amount', 0)}\n"
        f"Invoice: {invoice_url}\n"
        f"Pay: {pay_link}"
    )
    await TwilioAdapter.send_whatsapp(cust_phone, msg)
    return {"ok": True, "sent_to": cust_phone}


# ---------- Invoice PDF (public) ----------
@router.get("/invoices/{booking_id}.pdf")
async def invoice_pdf(booking_id: str):
    """Public PDF invoice. Anyone with the booking_id can view/download.
    Available once a bill has been generated (status BILLED or PAID)."""
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from fastapi.responses import Response

    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    if b.get("status") not in ("BILLED", "PAID"):
        raise HTTPException(400, "Bill not generated yet")
    cust = {"name": public_customer_name(b), "phone": b.get("customer_phone")}

    biz_name = os.environ.get("BUSINESS_NAME", "MacJit")
    biz_loc = os.environ.get("BUSINESS_LOCATION", "Varthur, Bangalore - 560087")
    biz_phone = os.environ.get("BUSINESS_PHONE", "+91 93534 01156")
    biz_email = os.environ.get("BUSINESS_EMAIL", "hello@macjit.com")
    biz_domain = os.environ.get("BUSINESS_DOMAIN", "macjit.com")

    def _watermark(canvas, _doc):
        """Center MacJit logo + text watermark, faded, on every page."""
        canvas.saveState()
        page_w, page_h = A4
        cx, cy = page_w / 2, page_h / 2
        # Outer ring (thin orange)
        canvas.setStrokeColor(colors.HexColor("#F26A21"))
        canvas.setFillColor(colors.HexColor("#F26A21"))
        canvas.setLineWidth(2)
        # Apply transparency for the whole watermark
        try:
            canvas.setFillAlpha(0.07)
            canvas.setStrokeAlpha(0.18)
        except Exception:
            pass
        canvas.circle(cx, cy, 70 * mm, stroke=1, fill=0)
        # Inner solid disk (faded)
        canvas.setFillColor(colors.HexColor("#1E2A44"))
        try:
            canvas.setFillAlpha(0.05)
        except Exception:
            pass
        canvas.circle(cx, cy, 60 * mm, stroke=0, fill=1)
        # Big "M" mark in center
        canvas.setFillColor(colors.HexColor("#F26A21"))
        try:
            canvas.setFillAlpha(0.12)
        except Exception:
            pass
        canvas.setFont("Helvetica-Bold", 200)
        canvas.drawCentredString(cx, cy - 65, "M")
        # Brand strip beneath
        canvas.setFillColor(colors.HexColor("#1E2A44"))
        try:
            canvas.setFillAlpha(0.15)
        except Exception:
            pass
        canvas.setFont("Helvetica-Bold", 28)
        canvas.drawCentredString(cx, cy - 95, "MACJIT")
        canvas.setFont("Helvetica", 10)
        canvas.drawCentredString(cx, cy - 110, "MECHANIC · JUST · IN · TIME")
        canvas.restoreState()

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=20 * mm,
                            leftMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=22, textColor=colors.HexColor("#1E2A44"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#F26A21"))
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=9, textColor=colors.HexColor("#555"))

    story = []
    # Header
    story.append(Paragraph(f"<b>{biz_name.upper()}</b> <font size=11 color='#F26A21'>· Mechanic Just In Time</font>", h1))
    story.append(Paragraph(f"{biz_loc} · {biz_phone} · {biz_email} · {biz_domain}", small))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(f"<b>TAX INVOICE</b>  &nbsp;&nbsp; <font color='#888'>#{booking_id[:8].upper()}</font>", h2))
    status_label = "PAID" if b.get("paid") else "DUE"
    color_box = "#16A34A" if b.get("paid") else "#F26A21"
    story.append(Paragraph(
        f"<font color='{color_box}'><b>STATUS: {status_label}</b></font> &nbsp;&nbsp; "
        f"Date: {(b.get('paid_at') or b.get('billed_at') or '')[:10]}",
        body))
    story.append(Spacer(1, 4 * mm))

    # Customer & vehicle
    info_data = [
        ["Customer", (cust or {}).get("name", "—"), "Vehicle", f"{b.get('car_make','')} {b.get('car_model','')}"],
        ["Phone", (cust or {}).get("phone", "—"), "Plate", b.get("plate_number", "—")],
        ["Service", b.get("service_type", "—"), "Mechanic", b.get("mechanic_name") or "—"],
    ]
    info_tbl = Table(info_data, colWidths=[28 * mm, 60 * mm, 28 * mm, 50 * mm])
    info_tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#888")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#888")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#eee")),
    ]))
    story.append(info_tbl)
    story.append(Spacer(1, 6 * mm))

    # Line items
    rows = [["#", "Item / Service", "SKU", "Qty", "Rate (\u20B9)", "Amount (\u20B9)"]]
    base_charge = b.get("subtotal", 0) - sum(i.get("subtotal", 0) for i in (b.get("items") or [])) - (b.get("extra_cost", 0) or 0)
    rows.append([
        "1",
        f"Service charge ({b.get('service_type','')})",
        "—", "1", f"{base_charge:.0f}", f"{base_charge:.0f}"
    ])
    for idx, it in enumerate(b.get("items") or [], start=2):
        rows.append([
            str(idx), it.get("name", ""), it.get("sku", ""),
            str(it.get("qty", 0)),
            f"{it.get('price', 0):.0f}",
            f"{it.get('subtotal', 0):.0f}",
        ])
    if b.get("extra_cost"):
        rows.append([str(len(rows)), f"Extra: {b.get('approval_reason','add-on')}", "—", "1",
                     f"{b['extra_cost']:.0f}", f"{b['extra_cost']:.0f}"])
    items_tbl = Table(rows, colWidths=[10 * mm, 70 * mm, 28 * mm, 14 * mm, 22 * mm, 26 * mm], repeatRows=1)
    items_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E2A44")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("ALIGN", (3, 0), (-1, -1), "RIGHT"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAF8F5")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#eee")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(items_tbl)
    story.append(Spacer(1, 4 * mm))

    # Totals
    tot_rows = [
        ["Subtotal", f"\u20B9{b.get('subtotal', 0):.0f}"],
    ]
    if b.get("loyalty_discount"):
        tot_rows.append([f"Loyalty discount ({b.get('loyalty_tier','')} – {b.get('discount_pct',0)}%)",
                         f"-\u20B9{b['loyalty_discount']:.0f}"])
    if b.get("extra_discount"):
        tot_rows.append(["Reception discount", f"-\u20B9{b['extra_discount']:.0f}"])
    tot_rows.append(["TOTAL PAID" if b.get("paid") else "AMOUNT DUE",
                     f"\u20B9{b.get('bill_amount', 0):.0f}"])
    tot_tbl = Table(tot_rows, colWidths=[120 * mm, 50 * mm], hAlign="RIGHT")
    tot_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, -1), (-1, -1), 13),
        ("TEXTCOLOR", (0, -1), (-1, -1), colors.HexColor("#F26A21")),
        ("LINEABOVE", (0, -1), (-1, -1), 1, colors.HexColor("#1E2A44")),
        ("TOPPADDING", (0, -1), (-1, -1), 6),
    ]))
    story.append(tot_tbl)
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(
        "Thank you for choosing MacJit. For any queries please reach us at "
        f"{biz_phone} or {biz_email}.",
        small))
    story.append(Paragraph("This is a computer-generated invoice; no signature required.", small))

    doc.build(story, onFirstPage=_watermark, onLaterPages=_watermark)
    pdf = buf.getvalue()
    buf.close()
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'inline; filename="MacJit-{booking_id[:8]}.pdf"'})



