from server import Depends, db, get_current_user  # noqa: F401

from fastapi import APIRouter
router = APIRouter()
# Auto-generated from routes.py section
# Section starts at line 1336

# ---------- NOTIFICATIONS ----------
@router.get("/notifications/me")
async def my_notifications(user=Depends(get_current_user)):
    return await db.notifications.find({"user_id": user["id"]}, {"_id": 0}).sort("ts", -1).limit(50).to_list(50)


@router.post("/notifications/{notif_id}/read")
async def mark_read(notif_id: str, user=Depends(get_current_user)):
    await db.notifications.update_one({"id": notif_id, "user_id": user["id"]}, {"$set": {"read": True}})
    return {"ok": True}


