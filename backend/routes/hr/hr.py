from server import BonusIn, Depends, HTTPException, HolidayIn, LeaveDecision, LeaveIn, Optional, ProfileUpdate, bus, datetime, db, get_current_user, now_iso, require_roles, timezone, uuid  # noqa: F401

from fastapi import APIRouter
router = APIRouter()
# Auto-generated from routes.py section
# Section starts at line 1386

# ---------- HR MODULE ----------
DEFAULT_LEAVE_BALANCE = {"casual": 12, "earned": 15, "sick": 8}
STAFF_ROLES = {"mechanic", "reception", "tester", "admin", "shopkeeper"}


def _staff_user(user):
    if user["role"] not in STAFF_ROLES:
        raise HTTPException(403, "Staff only")


@router.post("/hr/leaves")
async def apply_leave(data: LeaveIn, user=Depends(get_current_user)):
    _staff_user(user)
    rec = {"id": str(uuid.uuid4()), "user_id": user["id"], "user_name": user["name"],
           "user_role": user["role"], **data.model_dump(),
           "status": "PENDING", "created_at": now_iso(),
           "decided_at": None, "decided_by": None, "decision_note": None}
    await db.leaves.insert_one(dict(rec))
    rec.pop("_id", None)
    # notify all admins
    admin_ids = [u["id"] async for u in db.users.find({"role": "admin"}, {"_id": 0, "id": 1})]
    await bus.fanout(admin_ids, {"type": "LEAVE_REQUESTED", "data": rec, "ts": now_iso()})
    for aid in admin_ids:
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": aid, "event_type": "LEAVE_REQUESTED",
            "title": "Leave Request", "body": f"{user['name']} applied for {data.leave_type} leave",
            "read": False, "ts": now_iso(), "ref_id": rec["id"]
        })
    return rec


@router.get("/hr/leaves/me")
async def my_leaves(user=Depends(get_current_user)):
    _staff_user(user)
    return await db.leaves.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)


@router.get("/hr/leaves")
async def all_leaves(status: Optional[str] = None, user=Depends(require_roles("admin"))):
    q = {}
    if status:
        q["status"] = status.upper()
    return await db.leaves.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)


@router.patch("/hr/leaves/{leave_id}")
async def decide_leave(leave_id: str, data: LeaveDecision, user=Depends(require_roles("admin"))):
    decision = data.decision.upper()
    if decision not in ("APPROVED", "REJECTED"):
        raise HTTPException(400, "Invalid decision")
    await db.leaves.update_one({"id": leave_id}, {"$set": {
        "status": decision, "decided_at": now_iso(),
        "decided_by": user["name"], "decision_note": data.note
    }})
    rec = await db.leaves.find_one({"id": leave_id}, {"_id": 0})
    # notify employee
    await bus.fanout([rec["user_id"]], {"type": f"LEAVE_{decision}", "data": rec, "ts": now_iso()})
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()), "user_id": rec["user_id"], "event_type": f"LEAVE_{decision}",
        "title": f"Leave {decision.title()}",
        "body": f"Your {rec['leave_type']} leave was {decision.lower()}",
        "read": False, "ts": now_iso(), "ref_id": leave_id
    })
    return rec


# ---------- Attendance ----------
@router.post("/hr/attendance/punch")
async def punch(user=Depends(get_current_user)):
    _staff_user(user)
    today = datetime.now(timezone.utc).date().isoformat()
    rec = await db.attendance.find_one({"user_id": user["id"], "date": today})
    now = now_iso()
    if not rec:
        doc = {"id": str(uuid.uuid4()), "user_id": user["id"], "user_name": user["name"],
               "date": today, "punch_in": now, "punch_out": None}
        await db.attendance.insert_one(dict(doc))
        doc.pop("_id", None)
        return doc
    if not rec.get("punch_out"):
        await db.attendance.update_one({"id": rec["id"]}, {"$set": {"punch_out": now}})
    return await db.attendance.find_one({"id": rec["id"]}, {"_id": 0})


@router.get("/hr/attendance/me")
async def my_attendance(user=Depends(get_current_user)):
    _staff_user(user)
    return await db.attendance.find({"user_id": user["id"]}, {"_id": 0}).sort("date", -1).limit(60).to_list(60)


@router.get("/hr/attendance/all")
async def all_attendance(date: Optional[str] = None, user=Depends(require_roles("admin"))):
    q = {"date": date} if date else {}
    return await db.attendance.find(q, {"_id": 0}).sort("date", -1).to_list(500)


# ---------- Holidays ----------
@router.get("/hr/holidays")
async def list_holidays(user=Depends(get_current_user)):
    return await db.holidays.find({}, {"_id": 0}).sort("date", 1).to_list(200)


@router.post("/hr/holidays")
async def add_holiday(data: HolidayIn, user=Depends(require_roles("admin"))):
    doc = {"id": str(uuid.uuid4()), **data.model_dump(), "created_at": now_iso()}
    await db.holidays.insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


@router.delete("/hr/holidays/{hid}")
async def del_holiday(hid: str, user=Depends(require_roles("admin"))):
    await db.holidays.delete_one({"id": hid})
    return {"ok": True}


# ---------- Employee Profile ----------
@router.get("/hr/profile/me")
async def my_profile(user=Depends(get_current_user)):
    _staff_user(user)
    profile = await db.profiles.find_one({"user_id": user["id"]}, {"_id": 0}) or {}
    bal = profile.get("leave_balance") or DEFAULT_LEAVE_BALANCE
    used = {"casual": 0, "earned": 0, "sick": 0, "unpaid": 0}
    async for l in db.leaves.find({"user_id": user["id"], "status": "APPROVED"}, {"_id": 0}):
        try:
            days = (datetime.fromisoformat(l["end_date"]).date() - datetime.fromisoformat(l["start_date"]).date()).days + 1
            used[l["leave_type"]] = used.get(l["leave_type"], 0) + max(1, days)
        except Exception:
            pass
    timeline = await db.payroll_events.find({"user_id": user["id"]}, {"_id": 0}).sort("ts", -1).limit(50).to_list(50)
    return {"user": {k: v for k, v in user.items() if k != "password_hash"},
            "profile": profile, "leave_balance": bal, "leave_used": used,
            "timeline": timeline}


@router.patch("/hr/profile/{user_id}")
async def update_profile(user_id: str, data: ProfileUpdate, user=Depends(require_roles("admin"))):
    upd = {k: v for k, v in data.model_dump().items() if v is not None}
    upd["user_id"] = user_id
    await db.profiles.update_one({"user_id": user_id}, {"$set": upd}, upsert=True)
    return await db.profiles.find_one({"user_id": user_id}, {"_id": 0})


@router.post("/hr/payroll/event")
async def add_payroll_event(data: BonusIn, user=Depends(require_roles("admin"))):
    target = await db.users.find_one({"id": data.user_id}, {"_id": 0})
    if not target:
        raise HTTPException(404, "Employee not found")
    doc = {"id": str(uuid.uuid4()), "user_id": data.user_id, "user_name": target["name"],
           "amount": data.amount, "reason": data.reason, "event_type": data.event_type,
           "by": user["name"], "ts": now_iso()}
    await db.payroll_events.insert_one(dict(doc))
    doc.pop("_id", None)
    await bus.fanout([data.user_id], {"type": f"PAYROLL_{data.event_type.upper()}", "data": doc, "ts": now_iso()})
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()), "user_id": data.user_id,
        "event_type": f"PAYROLL_{data.event_type.upper()}",
        "title": data.event_type.replace("_", " ").title(),
        "body": f"₹{data.amount} · {data.reason}",
        "read": False, "ts": now_iso()
    })
    return doc


@router.get("/hr/profile/{user_id}")
async def admin_view_profile(user_id: str, user=Depends(require_roles("admin"))):
    profile = await db.profiles.find_one({"user_id": user_id}, {"_id": 0}) or {}
    target = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    timeline = await db.payroll_events.find({"user_id": user_id}, {"_id": 0}).sort("ts", -1).limit(50).to_list(50)
    return {"user": target, "profile": profile, "timeline": timeline}


