from server import app, client, datetime, db, hash_password, logger, now_iso, os, timedelta, timezone, uuid  # noqa: F401

# Auto-generated from routes.py section
# Section starts at line 2413

# ---------- Seeding ----------
# SECURITY NOTE: Admin seeding is DISABLED by default for security.
# To enable admin seeding, set SEED_ADMIN=true and configure ADMIN_* environment variables.
# This prevents accidental creation of default admin accounts in production.

# Only seed admin if explicitly enabled
SEED_ADMIN = os.environ.get('SEED_ADMIN', '').lower() == 'true'

if SEED_ADMIN:
    DEFAULT_ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
    DEFAULT_ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
    DEFAULT_ADMIN_NAME = os.environ.get('ADMIN_NAME')
    DEFAULT_ADMIN_PHONE = os.environ.get('ADMIN_PHONE')

    if not all([DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_NAME, DEFAULT_ADMIN_PHONE]):
        logger.error("SEED_ADMIN=true but ADMIN_* environment variables not set. Skipping admin seeding.")
        DEMO_USERS = []
    else:
        DEMO_USERS = [{
            "username": DEFAULT_ADMIN_USERNAME,
            "password": DEFAULT_ADMIN_PASSWORD,
            "name": DEFAULT_ADMIN_NAME,
            "role": "admin",
            "phone": DEFAULT_ADMIN_PHONE
        }]
        logger.info("Admin seeding enabled via SEED_ADMIN=true")
else:
    DEMO_USERS = []
    logger.info("Admin seeding disabled (set SEED_ADMIN=true to enable)")

DEMO_BAYS = [
    {"id": "bay-1", "name": "Bay A1", "type": "general"},
    {"id": "bay-2", "name": "Bay A2", "type": "general"},
    {"id": "bay-3", "name": "Bay B1", "type": "engine"},
    {"id": "bay-4", "name": "Bay B2", "type": "tire"},
]

DEMO_INVENTORY = [
    {"name": "Engine Oil 5W-30 Synthetic 4L (Castrol)", "sku": "OIL-CST-4L-5W30", "category": "Lubricants", "price": 2400, "stock": 18, "low_stock_threshold": 6,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=20)).isoformat(),
     "expiry_at": (datetime.now(timezone.utc) + timedelta(days=540)).isoformat()},
    {"name": "Engine Oil 0W-20 Synthetic 4L (Mobil1)", "sku": "OIL-MBL-4L-0W20", "category": "Lubricants", "price": 3200, "stock": 10, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=15)).isoformat(),
     "expiry_at": (datetime.now(timezone.utc) + timedelta(days=600)).isoformat()},
    {"name": "Oil Filter (Bosch)", "sku": "FLT-OIL-BSH", "category": "Filters", "price": 480, "stock": 22, "low_stock_threshold": 6,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=12)).isoformat()},
    {"name": "Air Filter (Bosch)", "sku": "FLT-AIR-BSH", "category": "Filters", "price": 620, "stock": 14, "low_stock_threshold": 5,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()},
    {"name": "Cabin AC Filter (carbon)", "sku": "FLT-AC-CRB", "category": "Filters", "price": 850, "stock": 9, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=18)).isoformat()},
    {"name": "Front Brake Pad Set (Bosch)", "sku": "BRK-PAD-FRT", "category": "Brakes", "price": 1850, "stock": 6, "low_stock_threshold": 3,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=22)).isoformat()},
    {"name": "Rear Brake Shoe Set", "sku": "BRK-SHOE-RR", "category": "Brakes", "price": 1450, "stock": 4, "low_stock_threshold": 3,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=25)).isoformat()},
    {"name": "Brake Fluid DOT-4 1L", "sku": "FLD-BRK-DOT4", "category": "Fluids", "price": 380, "stock": 16, "low_stock_threshold": 5,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()},
    {"name": "Coolant 5L (pre-mix)", "sku": "COL-5L", "category": "Fluids", "price": 950, "stock": 12, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()},
    {"name": "Wiper Blade Set 22\"+18\"", "sku": "WIP-22-18", "category": "Wipers", "price": 850, "stock": 8, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()},
    {"name": "12V 65Ah Battery (Exide)", "sku": "BAT-EXD-65", "category": "Battery", "price": 7200, "stock": 5, "low_stock_threshold": 2,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=18)).isoformat()},
    {"name": "Spark Plug Set of 4 (NGK Iridium)", "sku": "SPK-NGK-IR-4", "category": "Ignition", "price": 1600, "stock": 12, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=11)).isoformat()},
    {"name": "AC Refrigerant Gas R-1234yf 250g", "sku": "AC-GAS-R1234", "category": "AC", "price": 2800, "stock": 6, "low_stock_threshold": 3,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()},
    {"name": "Tyre 195/55 R16 (Apollo)", "sku": "TYR-195-55-16", "category": "Tyres", "price": 7200, "stock": 8, "low_stock_threshold": 4,
     "stocked_at": (datetime.now(timezone.utc) - timedelta(days=25)).isoformat()},
]


@app.on_event("startup")
async def startup():
    # One-time cleanup: remove any old hard-coded demo accounts from earlier seeds
    OLD_DEMO_USERNAMES = ["customer", "customer2", "reception", "mechanic",
                          "mechanic2", "tester", "admin", "shopkeeper"]
    deleted = await db.users.delete_many({"username": {"$in": OLD_DEMO_USERNAMES}})
    if deleted.deleted_count:
        logger.info(f"Cleaned up {deleted.deleted_count} legacy demo users")
    # Customers no longer have accounts — purge any leftovers from older builds.
    cust_purged = await db.users.delete_many({"role": "customer"})
    if cust_purged.deleted_count:
        logger.info(f"Purged {cust_purged.deleted_count} legacy customer accounts (customers no longer log in)")
    # Drop OTP collection if present (feature removed)
    try:
        await db.otps.drop()
    except Exception:
        pass
    # One-time cleanup: remove old 2-wheeler demo inventory
    OLD_INV_SKUS = ["OIL-CST-1L", "BRK-PAD-01", "FLT-AIR-01", "SPK-NGK-01",
                    "CHN-LUB-01", "TYR-90-17", "COL-500"]
    inv_del = await db.inventory.delete_many({"sku": {"$in": OLD_INV_SKUS}})
    if inv_del.deleted_count:
        logger.info(f"Cleaned up {inv_del.deleted_count} legacy 2-wheeler inventory items")
    # Idempotently seed/upgrade demo users (force admin role + correct password hash)
    if DEMO_USERS:
        for u in DEMO_USERS:
            existing = await db.users.find_one({"username": u["username"]})
            h = await hash_password(u["password"])
            if existing:
                # Update existing admin user
                update_data = {"name": u["name"], "role": u["role"], "phone": u["phone"], "password_hash": h}
                # If password changed, force reset
                if not existing.get("must_reset_password"):
                    update_data["must_reset_password"] = True
                await db.users.update_one(
                    {"id": existing["id"]},
                    {"$set": update_data}
                )
                logger.info(f"Upgraded existing user {u['username']} to {u['role']}")
            else:
                # Create new admin user with forced password reset
                doc = {"id": str(uuid.uuid4()), "username": u["username"], "name": u["name"],
                       "role": u["role"], "phone": u["phone"],
                       "password_hash": h, "created_at": now_iso(),
                       "must_reset_password": True}
                await db.users.insert_one(doc)  # seed users stored without encryption
                logger.warning(f"*** SECURITY WARNING *** Seeded admin user {u['username']} with password from environment variables. CHANGE IMMEDIATELY after first login!")
    else:
        logger.info("No admin users to seed (admin seeding disabled)")

    DEMO_SERVICES = [
        {"key": "general", "name": "General Service", "duration_min": 120, "base_price": 1200, "active": True},
        {"key": "oil-change", "name": "Oil & Filter Change", "duration_min": 45, "base_price": 800, "active": True},
        {"key": "full-service", "name": "Full Service", "duration_min": 210, "base_price": 3500, "active": True},
        {"key": "ac-service", "name": "AC Service", "duration_min": 90, "base_price": 1500, "active": True},
        {"key": "alignment", "name": "Wheel Alignment & Balancing", "duration_min": 60, "base_price": 700, "active": True},
        {"key": "brake", "name": "Brake Service", "duration_min": 75, "base_price": 1000, "active": True},
        {"key": "engine", "name": "Engine Repair / Diagnostics", "duration_min": 240, "base_price": 2500, "active": True},
    ]
    if await db.services.count_documents({}) == 0:
        for s in DEMO_SERVICES:
            await db.services.insert_one({"id": str(uuid.uuid4()), **s, "created_at": now_iso()})
        logger.info(f"Seeded {len(DEMO_SERVICES)} default services")

    if await db.bays.count_documents({}) == 0:
        for b in DEMO_BAYS:
            await db.bays.insert_one({**b, "created_at": now_iso()})
        logger.info(f"Seeded {len(DEMO_BAYS)} bays")
    if await db.inventory.count_documents({}) == 0:
        for i in DEMO_INVENTORY:
            await db.inventory.insert_one({"id": str(uuid.uuid4()), **i, "created_at": now_iso()})
        logger.info(f"Seeded {len(DEMO_INVENTORY)} inventory items")


@app.on_event("shutdown")
async def shutdown():
    client.close()


