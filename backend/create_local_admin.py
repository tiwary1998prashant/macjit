import asyncio
import uuid

from server import db, hash_password, now_iso


PHONE = "+919999999999"
USERNAME = "localadmin"
PASSWORD = "Admin@123456"


async def main():
    existing = await db.users.find_one({
        "$or": [
            {"username": USERNAME},
            {"phone": PHONE},
        ]
    })
    doc = {
        "username": USERNAME,
        "name": "Local Admin",
        "role": "admin",
        "phone": PHONE,
        "password_hash": await hash_password(PASSWORD),
        "initial_password": PASSWORD,
        "must_reset_password": True,
        "disabled": False,
    }
    if existing:
        await db.users.update_one({"id": existing["id"]}, {"$set": doc})
        print(f"updated {USERNAME} {PHONE}")
        return

    doc.update({"id": str(uuid.uuid4()), "created_at": now_iso()})
    await db.users.insert_one(doc)
    print(f"created {USERNAME} {PHONE}")


if __name__ == "__main__":
    asyncio.run(main())
