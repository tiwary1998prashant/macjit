from server import Depends, HTTPException, TwilioAdapter, bus, db, get_current_user, get_recipients_for_booking, now_iso, require_roles, uuid  # noqa: F401

from fastapi import APIRouter
router = APIRouter()
# Auto-generated from routes.py section
# Section starts at line 2153

# ---------- Mechanic photo capture (live progress photos) ----------
@router.post("/bookings/{booking_id}/photos")
async def upload_photo(booking_id: str, data: dict, user=Depends(require_roles("mechanic"))):
    """Accepts {data_url: 'data:image/jpeg;base64,...', caption?: ''} and stores."""
    data_url = data.get("data_url", "")
    if not data_url.startswith("data:image"):
        raise HTTPException(400, "Invalid image data")
    if len(data_url) > 2_500_000:  # ~2.5MB cap
        raise HTTPException(400, "Image too large (max 2MB)")
    photo = {
        "id": str(uuid.uuid4()),
        "booking_id": booking_id,
        "data_url": data_url,
        "caption": data.get("caption", ""),
        "captured_by": user["name"],
        "ts": now_iso(),
    }
    await db.service_photos.insert_one(dict(photo))
    photo.pop("_id", None)
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if b:
        recipients = await get_recipients_for_booking(b, include_admin=False)
        await bus.fanout(recipients, {"type": "PHOTO_CAPTURED", "data": {"booking_id": booking_id, "ts": photo["ts"]}, "ts": now_iso()})
    return {"id": photo["id"], "ts": photo["ts"]}


@router.get("/bookings/{booking_id}/photos")
async def list_photos(booking_id: str, user=Depends(get_current_user)):
    b = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if not b:
        raise HTTPException(404, "Not found")
    if user["role"] == "customer" and b.get("customer_id") != user["id"]:
        raise HTTPException(403, "Forbidden")
    return await db.service_photos.find({"booking_id": booking_id}, {"_id": 0}).sort("ts", -1).to_list(50)





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


