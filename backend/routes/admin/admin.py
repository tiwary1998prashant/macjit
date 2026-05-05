from server import Depends, datetime, db, require_roles, timedelta, timezone  # noqa: F401

from fastapi import APIRouter
router = APIRouter()
# Auto-generated from routes.py section
# Section starts at line 1348

# ---------- ADMIN ----------
@router.get("/admin/stats")
async def admin_stats(user=Depends(require_roles("admin", "reception"))):
    today = datetime.now(timezone.utc).date().isoformat()
    all_bookings = await db.bookings.find({}, {"_id": 0}).to_list(2000)
    today_done = [b for b in all_bookings if (b.get("paid_at") or "").startswith(today)]

    # Approved refunds (shop) — subtracted from revenue net
    approved_refunds = await db.refunds.find({"status": "APPROVED"}, {"_id": 0}).to_list(2000)
    refund_today_total = sum(r.get("amount", 0) for r in approved_refunds
                             if (r.get("decided_at") or "").startswith(today))

    revenue_today = sum(b.get("bill_amount", 0) for b in today_done) - refund_today_total
    by_status = {}
    for b in all_bookings:
        by_status[b["status"]] = by_status.get(b["status"], 0) + 1
    last_7 = []
    for i in range(6, -1, -1):
        d = (datetime.now(timezone.utc).date() - timedelta(days=i)).isoformat()
        day_bs = [b for b in all_bookings if (b.get("paid_at") or "").startswith(d)]
        day_refunds = sum(r.get("amount", 0) for r in approved_refunds
                          if (r.get("decided_at") or "").startswith(d))
        last_7.append({"date": d, "serviced": len(day_bs),
                       "revenue": sum(b.get("bill_amount", 0) for b in day_bs) - day_refunds})
    inv = await db.inventory.find({}, {"_id": 0}).to_list(1000)
    return {
        "today_serviced": len(today_done),
        "today_revenue": revenue_today,
        "today_refunds": refund_today_total,
        "active_bays": sum(1 for b in all_bookings if b["status"] == "IN_SERVICE"),
        "total_bookings": len(all_bookings),
        "by_status": by_status,
        "last_7_days": last_7,
        "low_stock_count": sum(1 for i in inv if 0 < i["stock"] <= i.get("low_stock_threshold", 5)),
        "out_of_stock_count": sum(1 for i in inv if i["stock"] <= 0),
    }


