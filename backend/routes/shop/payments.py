from fastapi import APIRouter
from server import HTTPException, Optional, RazorpayAdapter, Request, TwilioAdapter, _send_sale_invoice_whatsapp, bus, db, get_recipients_for_booking, hashlib, hmac, json, logger, now_iso, os, publish_event  # noqa: F401

router = APIRouter()

# Auto-generated from routes.py section
# Section starts at line 2214

# ---------- Razorpay Webhook ----------
@router.post("/webhooks/razorpay")
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


@router.get("/webhooks/razorpay/redirect")
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

