from server import Depends, HTTPException, LoginIn, Request, TwilioAdapter, _rate_check, db, get_current_user, hash_password, make_token, now_iso, os, require_roles, sanitize_str, uuid, verify_password  # noqa: F401
from utils.phone import _normalize_phone
from fastapi import APIRouter
router = APIRouter()
# Auto-generated from routes.py section
# Section starts at line 3

# ---------- API ROUTES ----------
# This module imports shared helpers from server.py and registers endpoints on api.

@router.post("/auth/login")
async def login(data: LoginIn, request: Request):
    """Staff-only login (admin / reception / mechanic / tester / shopkeeper).
    Customers do NOT log in — they track via vehicle number on the public page."""
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(f"login:{ip}", limit=10, window_sec=60):
        raise HTTPException(429, "Too many login attempts — try again in a minute")
    if data.username:
        q = {"username": sanitize_str(data.username)}
    else:
        phone_input = sanitize_str(data.phone)
        normalized_phone = _normalize_phone(phone_input)
        digits_only = "".join(c for c in (phone_input or "") if c.isdigit())
        raw_phone = digits_only[-10:] if len(digits_only) >= 10 else digits_only
        q = {
            "$or": [
                {"phone": normalized_phone},
                {"phone": raw_phone}
            ]
        }
    user = await db.users.find_one(q)
    if not user or not await verify_password(data.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    if user.get("role") == "customer":
        raise HTTPException(403, "Customers track bookings on the public page — no login required.")
    if user.get("active") is False:
        raise HTTPException(403, "Account disabled. Contact admin.")
    token = make_token(user["id"], user["role"])
    user.pop("_id", None); user.pop("password_hash", None)
    return {"token": token, "user": user, "must_reset_password": bool(user.get("must_reset_password"))}


@router.post("/auth/change-password")
async def change_password(data: dict, user=Depends(get_current_user)):
    """Force-reset flow on first login, or voluntary change."""
    new_pwd = (data.get("new_password") or "").strip()
    if len(new_pwd) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    h = await hash_password(new_pwd)
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"password_hash": h, "must_reset_password": False},
         "$unset": {"initial_password": ""}}
    )
    return {"ok": True}


# OTP login removed — customers now track via vehicle plate, no auth.




@router.post("/auth/reset-request")
async def reset_request(data: dict, request: Request):
    phone_input = sanitize_str(data.get("phone"))
    normalized_phone = _normalize_phone(phone_input)
    raw_digits = "".join(c for c in (phone_input or "") if c.isdigit())
    raw_phone = raw_digits[-10:] if len(raw_digits) >= 10 else raw_digits
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(f"reset:{ip}", limit=5, window_sec=300):
        raise HTTPException(429, "Too many reset requests — try again in 5 minutes")
    user = await db.users.find_one({
        "$or": [
            {"phone": normalized_phone},
            {"phone": raw_phone}
        ]
    })
    if not user:
        return {"ok": True}  # silent
    token = uuid.uuid4().hex
    await db.password_resets.insert_one({"token": token, "user_id": user["id"], "ts": now_iso()})
    link = f"{os.environ.get('PUBLIC_URL', '')}/reset?token={token}"
    await TwilioAdapter.send_sms(normalized_phone or raw_phone, f"MacJit password reset: {link}")
    return {"ok": True}


@router.post("/auth/reset-confirm")
async def reset_confirm(data: dict):
    token = data.get("token"); new_password = data.get("password")
    rec = await db.password_resets.find_one({"token": token})
    if not rec:
        raise HTTPException(400, "Invalid token")
    h = await hash_password(new_password)
    await db.users.update_one({"id": rec["user_id"]}, {"$set": {"password_hash": h}})
    await db.password_resets.delete_one({"token": token})
    return {"ok": True}


@router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


@router.get("/users")
async def list_users(user=Depends(require_roles("reception", "admin"))):
    return await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(500)


@router.get("/users/by-role/{role}")
async def users_by_role(role: str, user=Depends(get_current_user)):
    return await db.users.find({"role": role}, {"_id": 0, "password_hash": 0}).to_list(500)


