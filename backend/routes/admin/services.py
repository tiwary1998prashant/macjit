from server import Depends, HTTPException, PricingIn, ServiceIn, db, get_current_user, now_iso, require_roles, uuid  # noqa: F401
from fastapi import APIRouter
router = APIRouter()
from constants import DEFAULT_PRICES, LOYALTY_DISCOUNT

# Auto-generated from routes.py section
# Section starts at line 955

# ---------- Pricing ----------



# ---------- SERVICES (dynamic, admin-managed) ----------
@router.get("/services")
async def list_services(user=Depends(get_current_user)):
    """Return all services (active and inactive) for display. Reception uses active ones for booking."""
    return await db.services.find({}, {"_id": 0}).sort("key", 1).to_list(100)


@router.get("/services/active")
async def list_active_services(user=Depends(get_current_user)):
    """Return only active services (for booking dropdowns)."""
    return await db.services.find({"active": True}, {"_id": 0}).sort("key", 1).to_list(100)


@router.post("/services")
async def create_service(data: ServiceIn, user=Depends(require_roles("admin"))):
    existing = await db.services.find_one({"key": data.key})
    if existing:
        raise HTTPException(400, f"Service key '{data.key}' already exists. Use PATCH to update.")
    doc = {"id": str(uuid.uuid4()), **data.model_dump(), "created_at": now_iso()}
    await db.services.insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.patch("/services/{service_id}")
async def update_service(service_id: str, data: dict, user=Depends(require_roles("admin"))):
    allowed = {"name", "duration_min", "base_price", "active"}
    upd = {k: v for k, v in data.items() if k in allowed}
    if not upd:
        raise HTTPException(400, "Nothing to update. Allowed fields: name, duration_min, base_price, active.")
    await db.services.update_one({"id": service_id}, {"$set": upd})
    svc = await db.services.find_one({"id": service_id}, {"_id": 0})
    if not svc:
        raise HTTPException(404, "Service not found")
    return svc


@router.delete("/services/{service_id}")
async def delete_service(service_id: str, user=Depends(require_roles("admin"))):
    svc = await db.services.find_one({"id": service_id})
    if not svc:
        raise HTTPException(404, "Service not found")
    await db.services.delete_one({"id": service_id})
    return {"ok": True}

@router.get("/pricing")
async def list_pricing(user=Depends(get_current_user)):
    items = await db.service_prices.find({}, {"_id": 0}).to_list(50)
    have = {i["service_type"] for i in items}
    for st, p in DEFAULT_PRICES.items():
        if st not in have:
            items.append({"service_type": st, "base_price": p, "default": True})
    return items


@router.post("/pricing")
async def upsert_pricing(data: PricingIn, user=Depends(require_roles("admin"))):
    await db.service_prices.update_one({"service_type": data.service_type}, {"$set": data.model_dump()}, upsert=True)
    return await db.service_prices.find_one({"service_type": data.service_type}, {"_id": 0})


