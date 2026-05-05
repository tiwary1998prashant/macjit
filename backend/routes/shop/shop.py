from server import Depends, HTTPException, Optional, RazorpayAdapter, RefundDecision, RefundIn, ShopSaleIn, TwilioAdapter, _send_sale_invoice_whatsapp, bus, datetime, db, now_iso, public_bookings, require_roles, timedelta, timezone, uuid  # noqa: F401

from fastapi import APIRouter
router = APIRouter()
# Auto-generated from routes.py section
# Section starts at line 1773

# ---------- SHOP MODULE (walk-in parts counter, shares inventory) ----------
@router.post("/shop/sales")
async def create_sale(data: ShopSaleIn, user=Depends(require_roles("shopkeeper", "admin", "reception"))):
    if not data.items:
        raise HTTPException(400, "Cart empty")
    lines = []
    total = 0.0
    for line in data.items:
        inv = await db.inventory.find_one({"id": line.inventory_id})
        if not inv:
            raise HTTPException(404, f"Item not found: {line.inventory_id}")
        if inv["stock"] < line.qty:
            raise HTTPException(400, f"Insufficient stock for {inv['name']}")
        subtotal = inv["price"] * line.qty
        lines.append({"inventory_id": inv["id"], "name": inv["name"], "sku": inv["sku"],
                      "qty": line.qty, "price": inv["price"], "subtotal": subtotal})
        total += subtotal
        await db.inventory.update_one({"id": inv["id"]}, {"$inc": {"stock": -line.qty}})

    fitting_charge = round(max(0.0, float(data.fitting_charge or 0)), 2)
    gst_percent = round(max(0.0, float(data.gst_percent or 0)), 2)
    taxable_amount = total + fitting_charge
    gst_amount = round(taxable_amount * gst_percent / 100, 2)
    grand_total = round(taxable_amount + gst_amount, 2)

    sale_id = str(uuid.uuid4())
    payment_link = None
    rzp_payment_link_id = None
    if data.payment_method == "razorpay":
        notes = {"type": "shop_sale", "sale_id": sale_id,
                 "customer": data.customer_name or "Walk-in"}
        payment_link, rzp_payment_link_id = await RazorpayAdapter.create_payment_link_full(
            grand_total, sale_id, data.customer_phone or "", notes=notes
        )

    sale = {
        "id": sale_id,
        "customer_name": data.customer_name or "Walk-in",
        "customer_phone": data.customer_phone or "",
        "items": lines,
        "subtotal": total,
        "fitting_charge": fitting_charge,
        "gst_percent": gst_percent,
        "gst_amount": gst_amount,
        "total": grand_total,
        "payment_method": data.payment_method,
        "payment_link": payment_link,
        "rzp_payment_link_id": rzp_payment_link_id,
        "paid": data.payment_method == "cash",  # cash assumed paid at counter
        "shopkeeper_id": user["id"], "shopkeeper_name": user["name"],
        "created_at": now_iso(),
        "paid_at": now_iso() if data.payment_method == "cash" else None,
    }
    await db.shop_sales.insert_one(dict(sale))
    sale.pop("_id", None)
    if data.customer_phone:
        if data.payment_method == "razorpay" and payment_link:
            # Razorpay: send the payment link now; invoice auto-sent after payment via webhook
            pay_msg = (
                f"MacJit - Your bill of ₹{grand_total:.0f} is ready.\n"
                f"Pay securely here: {payment_link}\n"
                f"Your invoice will be sent to you after payment. Thank you!"
            )
            await TwilioAdapter.send_sms(data.customer_phone, pay_msg)
        else:
            # Cash / other: payment already done — send full invoice immediately
            await _send_sale_invoice_whatsapp(sale)
    # notify admin
    admin_ids = [u["id"] async for u in db.users.find({"role": "admin"}, {"_id": 0, "id": 1})]
    await bus.fanout(admin_ids, {"type": "SHOP_SALE", "data": sale, "ts": now_iso()})
    return sale


@router.post("/shop/sales/{sale_id}/pay")
async def mark_sale_paid(sale_id: str, user=Depends(require_roles("shopkeeper", "admin", "reception"))):
    await db.shop_sales.update_one({"id": sale_id}, {"$set": {"paid": True, "paid_at": now_iso()}})
    sale = await db.shop_sales.find_one({"id": sale_id}, {"_id": 0})
    if sale:
        await _send_sale_invoice_whatsapp(sale)
    return sale


@router.get("/shop/sales")
async def list_sales(user=Depends(require_roles("shopkeeper", "admin", "reception"))):
    return await db.shop_sales.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)


@router.get("/shop/stats")
async def shop_stats(user=Depends(require_roles("shopkeeper", "admin", "reception"))):
    today = datetime.now(timezone.utc).date().isoformat()
    sales = await db.shop_sales.find({}, {"_id": 0}).to_list(2000)
    today_sales = [s for s in sales if (s.get("created_at") or "").startswith(today)]
    today_paid = [s for s in today_sales if s.get("paid")]

    # Approved shop refunds (subtract from revenue net)
    approved_refunds = await db.refunds.find({"status": "APPROVED"}, {"_id": 0}).to_list(2000)
    refund_today_total = sum(r.get("amount", 0) for r in approved_refunds
                             if (r.get("decided_at") or "").startswith(today))

    last_7 = []
    for i in range(6, -1, -1):
        d = (datetime.now(timezone.utc).date() - timedelta(days=i)).isoformat()
        day = [s for s in sales if (s.get("created_at") or "").startswith(d) and s.get("paid")]
        day_refunds = sum(r.get("amount", 0) for r in approved_refunds
                          if (r.get("decided_at") or "").startswith(d))
        last_7.append({"date": d, "sales": len(day),
                       "revenue": sum(s.get("total", 0) for s in day) - day_refunds})
    # Top fast-movers (last 7 days, by units sold)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    movers = {}
    for s in sales:
        if (s.get("created_at") or "") < cutoff:
            continue
        for it in s.get("items", []):
            k = it.get("inventory_id")
            if k not in movers:
                movers[k] = {"inventory_id": k, "name": it["name"], "sku": it["sku"], "units": 0, "revenue": 0}
            movers[k]["units"] += it.get("qty", 0)
            movers[k]["revenue"] += it.get("subtotal", 0)
    fast_movers = sorted(movers.values(), key=lambda x: x["units"], reverse=True)[:5]
    return {
        "today_count": len(today_sales),
        "today_revenue": sum(s.get("total", 0) for s in today_paid) - refund_today_total,
        "today_refunds": refund_today_total,
        "pending_count": sum(1 for s in sales if not s.get("paid")),
        "last_7_days": last_7,
        "total_sales": len(sales),
        "fast_movers": fast_movers,
    }


# ---------- REFUNDS (shop) ----------
@router.post("/shop/refunds")
async def raise_refund(data: RefundIn, user=Depends(require_roles("shopkeeper", "admin"))):
    """Shopkeeper raises a refund request for a paid shop sale.
    Admin must approve before stock is restored and sale is flagged refunded."""
    sale = await db.shop_sales.find_one({"id": data.sale_id}, {"_id": 0})
    if not sale:
        raise HTTPException(404, "Sale not found")
    if not sale.get("paid"):
        raise HTTPException(400, "Only paid sales can be refunded")
    if sale.get("refund_status") in ("PENDING", "APPROVED"):
        raise HTTPException(400, f"Refund already {sale['refund_status']}")

    # Build refund line items (full or partial)
    sale_items_by_id = {it["inventory_id"]: it for it in sale.get("items", [])}
    refund_items = []
    if data.items:
        for line in data.items:
            base = sale_items_by_id.get(line.inventory_id)
            if not base:
                raise HTTPException(400, f"Item {line.inventory_id} not in sale")
            if line.qty <= 0 or line.qty > base["qty"]:
                raise HTTPException(400, f"Invalid qty for {base['name']}")
            refund_items.append({**base, "qty": line.qty,
                                 "subtotal": base["price"] * line.qty})
    else:
        refund_items = [dict(it) for it in sale.get("items", [])]
    refund_total = sum(it["subtotal"] for it in refund_items)

    refund = {
        "id": str(uuid.uuid4()),
        "sale_id": sale["id"],
        "customer_name": sale.get("customer_name"),
        "customer_phone": sale.get("customer_phone"),
        "items": refund_items,
        "amount": refund_total,
        "reason": data.reason,
        "status": "PENDING",
        "raised_by_id": user["id"],
        "raised_by_name": user["name"],
        "raised_at": now_iso(),
        "decided_by_name": None,
        "decided_at": None,
        "decision_note": "",
    }
    await db.refunds.insert_one(dict(refund))
    refund.pop("_id", None)
    await db.shop_sales.update_one({"id": sale["id"]}, {"$set": {"refund_status": "PENDING"}})

    admin_ids = [u["id"] async for u in db.users.find({"role": "admin"}, {"_id": 0, "id": 1})]
    await bus.fanout(admin_ids, {"type": "REFUND_RAISED", "data": refund, "ts": now_iso()})
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": admin_ids[0] if admin_ids else "",
        "event_type": "REFUND_RAISED",
        "title": "Refund request",
        "body": f"₹{refund_total:.0f} · {sale.get('customer_name','Walk-in')} · {data.reason[:40]}",
        "read": False, "ts": now_iso(),
    })
    return refund


@router.get("/shop/refunds")
async def my_refunds(user=Depends(require_roles("shopkeeper", "admin", "reception"))):
    q = {} if user.get("role") == "admin" else {"raised_by_id": user["id"]}
    return await db.refunds.find(q, {"_id": 0}).sort("raised_at", -1).to_list(200)


@router.get("/admin/refunds")
async def admin_list_refunds(status: Optional[str] = None,
                             user=Depends(require_roles("admin"))):
    q = {}
    if status:
        q["status"] = status.upper()
    return await db.refunds.find(q, {"_id": 0}).sort("raised_at", -1).to_list(500)


@router.post("/admin/refunds/{refund_id}/decision")
async def decide_refund(refund_id: str, data: RefundDecision,
                        user=Depends(require_roles("admin"))):
    decision = (data.decision or "").lower()
    if decision not in ("approved", "rejected"):
        raise HTTPException(400, "decision must be 'approved' or 'rejected'")
    refund = await db.refunds.find_one({"id": refund_id}, {"_id": 0})
    if not refund:
        raise HTTPException(404, "Refund not found")
    if refund["status"] != "PENDING":
        raise HTTPException(400, f"Already {refund['status']}")

    new_status = "APPROVED" if decision == "approved" else "REJECTED"
    await db.refunds.update_one({"id": refund_id}, {"$set": {
        "status": new_status,
        "decided_by_name": user["name"],
        "decided_at": now_iso(),
        "decision_note": data.note or "",
    }})

    if new_status == "APPROVED":
        # Restore stock & mark sale refunded
        for it in refund["items"]:
            await db.inventory.update_one({"id": it["inventory_id"]},
                                          {"$inc": {"stock": it["qty"]}})
        await db.shop_sales.update_one({"id": refund["sale_id"]}, {"$set": {
            "refund_status": "APPROVED",
            "refunded_amount": refund["amount"],
            "refunded_at": now_iso(),
        }})
    else:
        await db.shop_sales.update_one({"id": refund["sale_id"]},
                                       {"$set": {"refund_status": "REJECTED"}})

    # Notify shopkeeper
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": refund["raised_by_id"],
        "event_type": f"REFUND_{new_status}",
        "title": f"Refund {new_status.lower()}",
        "body": f"₹{refund['amount']:.0f} · {data.note or 'no note'}",
        "read": False, "ts": now_iso(),
    })
    await bus.fanout([refund["raised_by_id"]],
                     {"type": f"REFUND_{new_status}", "data": refund, "ts": now_iso()})
    return await db.refunds.find_one({"id": refund_id}, {"_id": 0})


# ---------- ADMIN TRANSACTIONS (Paytm-style unified history) ----------
@router.get("/admin/transactions")
async def admin_transactions(type: str = "all", q: str = "", limit: int = 200,
                             date_from: Optional[str] = None, date_to: Optional[str] = None,
                             period: Optional[str] = None,
                             user=Depends(require_roles("admin"))):
    """Unified payment history across services (paid bookings) and shop (paid counter sales).
    Filter `type`: all | service | shop. `q` matches customer name/phone/plate/sku."""
    type = (type or "all").lower()
    items: list = []

    if type in ("all", "service"):
        bookings = public_bookings(await db.bookings.find({"paid": True}, {"_id": 0}).sort("paid_at", -1).to_list(500))
        for b in bookings:
            items.append({
                "id": b["id"],
                "kind": "service",
                "ref": b["id"][:8].upper(),
                "customer_name": b.get("customer_name") or "—",
                "customer_phone": b.get("customer_phone") or "",
                "title": f"{b.get('service_type','service')} · {b.get('plate_number','')}",
                "subtitle": f"{b.get('car_make','')} {b.get('car_model','')}".strip() or "—",
                "amount": b.get("bill_amount", 0),
                "method": b.get("payment_method") or ("razorpay" if b.get("razorpay_payment_id") else "cash"),
                "ts": b.get("paid_at") or b.get("billed_at") or b.get("created_at"),
                "items": b.get("items") or [],
                "extra": {"mechanic": b.get("mechanic_name") or "—",
                          "bay": b.get("bay_name") or "—",
                          "razorpay_payment_id": b.get("razorpay_payment_id")},
                "invoice_url": f"/api/invoices/{b['id']}.pdf",
            })

    if type in ("all", "shop"):
        sales = await db.shop_sales.find({"paid": True}, {"_id": 0}).sort("paid_at", -1).to_list(500)
        for s in sales:
            items.append({
                "id": s["id"],
                "kind": "shop",
                "ref": s["id"][:8].upper(),
                "customer_name": s.get("customer_name") or "Walk-in",
                "customer_phone": s.get("customer_phone") or "",
                "title": f"{len(s.get('items', []))} item(s) · {s.get('shopkeeper_name','counter')}",
                "subtitle": ", ".join((it.get("name") or "")[:24] for it in (s.get("items") or [])[:2]) or "—",
                "amount": s.get("total", 0),
                "method": s.get("payment_method") or "cash",
                "ts": s.get("paid_at") or s.get("created_at"),
                "items": s.get("items") or [],
                "extra": {"refund_status": s.get("refund_status"),
                          "refunded_amount": s.get("refunded_amount")},
                "invoice_url": None,
            })

        # Add an explicit refund row (negative amount) for each approved refund
        approved_refunds = await db.refunds.find({"status": "APPROVED"}, {"_id": 0}).to_list(500)
        for r in approved_refunds:
            items.append({
                "id": r["id"],
                "kind": "refund",
                "ref": "RF-" + r["id"][:6].upper(),
                "customer_name": r.get("customer_name") or "Walk-in",
                "customer_phone": r.get("customer_phone") or "",
                "title": f"Refund · sale #{r.get('sale_id','')[:8]}",
                "subtitle": (r.get("reason") or "")[:60] or "—",
                "amount": -float(r.get("amount", 0)),
                "method": "refund",
                "ts": r.get("decided_at") or r.get("raised_at"),
                "items": r.get("items") or [],
                "extra": {"raised_by": r.get("raised_by_name"),
                          "decided_by": r.get("decided_by_name"),
                          "note": r.get("decision_note"),
                          "sale_id": r.get("sale_id")},
                "invoice_url": None,
            })

    # --- Period/date filter ---
    _now = datetime.now(timezone.utc)
    if period == "today":
        date_from = _now.date().isoformat()
        date_to = date_from
    elif period == "week":
        date_from = (_now.date() - timedelta(days=6)).isoformat()
        date_to = _now.date().isoformat()
    elif period == "month":
        date_from = (_now.date() - timedelta(days=29)).isoformat()
        date_to = _now.date().isoformat()
    if date_from or date_to:
        def _in_date_range(t):
            ts = (t.get("ts") or "")[:10]
            if date_from and ts < date_from:
                return False
            if date_to and ts > date_to:
                return False
            return True
        items = [t for t in items if _in_date_range(t)]

    if q:
        ql = q.lower()
        def match(t):
            blob = " ".join([
                str(t.get("customer_name") or ""),
                str(t.get("customer_phone") or ""),
                str(t.get("title") or ""),
                str(t.get("ref") or ""),
                " ".join((it.get("name", "") + " " + it.get("sku", "")) for it in t.get("items", [])),
            ]).lower()
            return ql in blob
        items = [t for t in items if match(t)]

    items.sort(key=lambda x: x.get("ts") or "", reverse=True)
    items = items[:limit]
    gross_in = sum(t["amount"] for t in items if t["amount"] > 0)
    refund_out = -sum(t["amount"] for t in items if t["amount"] < 0)
    return {
        "transactions": items,
        "total_amount": gross_in - refund_out,   # NET (after refunds)
        "gross_amount": gross_in,                # before refunds
        "refund_amount": refund_out,             # total refunded out
        "count": len(items),
        "service_count": sum(1 for t in items if t["kind"] == "service"),
        "shop_count": sum(1 for t in items if t["kind"] == "shop"),
        "refund_count": sum(1 for t in items if t["kind"] == "refund"),
    }


