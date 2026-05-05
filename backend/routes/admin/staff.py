from server import Depends, HTTPException, StaffCreate, TwilioAdapter, db, hash_password, logger, now_iso, require_roles, uuid  # noqa: F401
from utils.phone import _normalize_phone
from fastapi import APIRouter
router = APIRouter()
# Auto-generated from routes.py section
# Section starts at line 1068

# ---------- Staff management ----------
ALLOWED_STAFF_ROLES = ("mechanic", "reception", "tester", "shopkeeper", "admin")


@router.get("/admin/staff")
async def list_staff(user=Depends(require_roles("admin"))):
    """Returns staff with their initial password while it has not yet been changed,
    so the admin can pass it on to the employee. Password disappears once the
    employee logs in and resets it."""
    return await db.users.find(
        {"role": {"$in": list(ALLOWED_STAFF_ROLES)}},
        {"_id": 0, "password_hash": 0}
    ).to_list(500)


@router.post("/admin/staff")
async def create_staff(data: StaffCreate, user=Depends(require_roles("admin"))):
    if data.role not in ALLOWED_STAFF_ROLES:
        raise HTTPException(400, "Invalid role")
    phone = _normalize_phone(data.phone)
    if not phone or len(phone) < 10:
        raise HTTPException(400, "Valid phone required")
    raw_digits = "".join(c for c in phone if c.isdigit())
    raw_phone = raw_digits[-10:] if len(raw_digits) >= 10 else raw_digits
    if await db.users.find_one({
        "$or": [
            {"phone": phone},
            {"phone": raw_phone}
        ]
    }):
        raise HTTPException(400, "Phone already registered")
    initial_pwd = (data.password or "").strip() or uuid.uuid4().hex[:8]
    if len(initial_pwd) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    doc = {"id": str(uuid.uuid4()), "username": phone, "name": data.name,
           "phone": phone, "role": data.role,
           "password_hash": await hash_password(initial_pwd),
           "initial_password": initial_pwd,
           "must_reset_password": True,
           "active": True, "created_at": now_iso(), "created_by": user["id"]}
    await db.users.insert_one(dict(doc))
    # Best-effort SMS so the employee gets the initial password directly.
    try:
        await TwilioAdapter.send_sms(
            phone,
            f"MacJit: Welcome {data.name}! Login at the staff page with phone {phone} "
            f"and temporary password: {initial_pwd}. You will be asked to set a new password."
        )
    except Exception as e:
        logger.warning(f"Staff invite SMS failed: {e}")
    doc.pop("password_hash", None)
    return doc


@router.patch("/admin/staff/{user_id}")
async def update_staff(user_id: str, data: dict, user=Depends(require_roles("admin"))):
    data.pop("_id", None); data.pop("id", None); data.pop("password_hash", None)
    await db.users.update_one({"id": user_id}, {"$set": data})
    return await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})


@router.delete("/admin/staff/{user_id}")
async def delete_staff(user_id: str, user=Depends(require_roles("admin"))):
    target = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not target:
        raise HTTPException(404, "Staff not found")
    if target.get("role") not in ALLOWED_STAFF_ROLES:
        raise HTTPException(400, "Not a staff account")
    if target["id"] == user["id"]:
        raise HTTPException(400, "You cannot remove your own account")
    if target.get("role") == "admin":
        admin_count = await db.users.count_documents({"role": "admin"})
        if admin_count <= 1:
            raise HTTPException(400, "Cannot remove the only admin")
    await db.users.delete_one({"id": user_id})
    return {"ok": True}


@router.post("/admin/staff/{user_id}/reset-password")
async def reset_staff_password(user_id: str, user=Depends(require_roles("admin"))):
    """Generate a fresh temporary password for a staff member and force a reset on next login."""
    target = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not target or target.get("role") not in ALLOWED_STAFF_ROLES:
        raise HTTPException(404, "Staff not found")
    new_pwd = uuid.uuid4().hex[:8]
    h = await hash_password(new_pwd)
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"password_hash": h, "initial_password": new_pwd, "must_reset_password": True}}
    )
    return {"ok": True, "initial_password": new_pwd}


