from server import Depends, HTTPException, db, public_booking, public_bookings, public_customer_name, require_roles  # noqa: F401
from fastapi import APIRouter
from utils.phone import _normalize_phone
router = APIRouter()
from constants import LOYALTY_DISCOUNT

# Auto-generated from routes.py section
# Section starts at line 1023

# ---------- Customer history & loyalty (no accounts; aggregated from bookings) ----------
@router.get("/customers")
async def list_customers(user=Depends(require_roles("reception", "admin"))):
    """Aggregate unique customers from bookings (since customers have no login)."""
    pipeline = [
        {"$group": {
            "_id": "$customer_phone",
            "name": {"$last": "$customer_name"},
            "name_plain": {"$last": "$customer_name_plain"},
            "phone": {"$last": "$customer_phone"},
            "total_spent": {"$sum": {"$cond": [{"$eq": ["$paid", True]}, "$bill_amount", 0]}},
            "visits": {"$sum": 1},
            "last_visit": {"$max": "$created_at"},
        }},
        {"$match": {"_id": {"$ne": None}}},
        {"$sort": {"last_visit": -1}},
    ]
    items = []
    async for c in db.bookings.aggregate(pipeline):
        spent = c.get("total_spent", 0) or 0
        tier = "GOLD" if spent >= 25000 else ("SILVER" if spent >= 10000 else "BRONZE")
        items.append({
            "id": f"walkin-{c['_id']}",
            "name": c.get("name_plain") or public_customer_name({"customer_name": c.get("name")}), "phone": c.get("phone"),
            "total_spent": spent, "loyalty_tier": tier, "visits": c.get("visits", 0),
            "last_visit": c.get("last_visit"),
        })
    return items


@router.get("/customers/{customer_id}/history")
async def customer_history(customer_id: str, user=Depends(require_roles("reception", "admin"))):
    """customer_id is `walkin-{phone}` (matches the IDs returned by /customers)."""
    phone = customer_id.replace("walkin-", "", 1) if customer_id.startswith("walkin-") else customer_id
    normalized_phone = _normalize_phone(phone)
    digits_only = "".join(c for c in phone if c.isdigit())
    raw_phone = digits_only[-10:] if len(digits_only) >= 10 else digits_only
    bookings = await db.bookings.find(
        {"$or": [{"customer_phone": normalized_phone}, {"customer_phone": raw_phone}]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(500)
    if not bookings:
        raise HTTPException(404, "Not found")
    spent = sum(b.get("bill_amount", 0) for b in bookings if b.get("paid"))
    tier = "GOLD" if spent >= 25000 else ("SILVER" if spent >= 10000 else "BRONZE")
    bookings = public_bookings(bookings)
    cust = {"id": customer_id, "name": public_customer_name(bookings[0]), "phone": phone,
            "total_spent": spent, "loyalty_tier": tier}
    return {"customer": cust, "bookings": bookings,
            "total_spent": spent, "loyalty_tier": tier,
            "discount_pct": LOYALTY_DISCOUNT.get(tier, 0)}


