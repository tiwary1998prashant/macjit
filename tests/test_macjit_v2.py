"""Backend tests for MacJit v2 (4-wheeler conversion).

Covers:
- New admin login (username + phone) for Prashant Tiwary
- Old demo logins are gone (cleanup ran)
- Public enquiry endpoint + admin list/patch
- Inventory bulk-upload (CSV + XLSX, upsert by SKU, error reporting)
- Booking with car_make/car_model + mechanic_phone after auto-assign
- Inventory lists car-specific items (e.g. OIL-CST-4L-5W30)
"""
import io
import os
import uuid
import csv
from pathlib import Path

import pytest
import requests
from dotenv import load_dotenv

# Load test environment variables from .env.test
test_env_file = Path(__file__).parent.parent / ".env.test"
if test_env_file.exists():
    load_dotenv(test_env_file, override=True)
else:
    # Fallback to example if .env.test doesn't exist
    load_dotenv(Path(__file__).parent.parent / ".env.test.example", override=True)

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # Fallback for testing inside container
    try:
        with open("/app/frontend/.env") as f:
            for line in f:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
                    break
    except FileNotFoundError:
        BASE_URL = "http://localhost:8000"

API = f"{BASE_URL}/api"
ADMIN_USER = os.environ.get("ADMIN_USERNAME", "test-admin")
ADMIN_PHONE = os.environ.get("ADMIN_PHONE", "+919999999999")
ADMIN_PWD = os.environ.get("ADMIN_PASSWORD", "test-password-123")


# ---------- fixtures ----------
@pytest.fixture(scope="session")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="session")
def admin_token(session):
    r = session.post(f"{API}/auth/login",
                     json={"username": ADMIN_USER, "password": ADMIN_PWD})
    if r.status_code != 200:
        pytest.skip(f"admin login failed: {r.status_code} {r.text}")
    return r.json()["token"]


@pytest.fixture(scope="session")
def admin_session(session, admin_token):
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json",
                      "Authorization": f"Bearer {admin_token}"})
    return s


# ---------- Auth ----------
class TestAuth:
    def test_login_with_username(self, session):
        r = session.post(f"{API}/auth/login",
                         json={"username": ADMIN_USER, "password": ADMIN_PWD})
        assert r.status_code == 200, r.text
        data = r.json()
        assert "token" in data and isinstance(data["token"], str) and data["token"]
        assert data["user"]["role"] == "admin"
        assert data["user"]["name"] == "Prashant Tiwary"
        assert data["user"]["username"] == ADMIN_USER

    def test_login_with_phone(self, session):
        r = session.post(f"{API}/auth/login",
                         json={"phone": ADMIN_PHONE, "password": ADMIN_PWD})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["user"]["role"] == "admin"
        assert data["user"]["phone"] == ADMIN_PHONE

    def test_login_wrong_password(self, session):
        r = session.post(f"{API}/auth/login",
                         json={"username": ADMIN_USER, "password": "wrong"})
        assert r.status_code == 401

    @pytest.mark.parametrize("creds", [
        {"username": "admin", "password": "admin123"},
        {"username": "customer", "password": "customer123"},
        {"username": "mechanic", "password": "mechanic123"},
        {"username": "reception", "password": "admin123"},
        {"username": "tester", "password": "admin123"},
    ])
    def test_old_demo_logins_fail(self, session, creds):
        r = session.post(f"{API}/auth/login", json=creds)
        assert r.status_code == 401, (
            f"Old demo login {creds['username']} unexpectedly succeeded: {r.text}"
        )


# ---------- Enquiries ----------
class TestEnquiries:
    created_id = None

    def test_create_enquiry_public_no_auth(self, session):
        payload = {
            "name": f"TEST_Enquiry_{uuid.uuid4().hex[:6]}",
            "phone": "+911234567890",
            "email": "test@example.com",
            "car_make": "Maruti",
            "car_model": "Swift",
            "service_interest": "general service",
            "message": "Need oil change",
        }
        # No auth header — must be public
        r = requests.post(f"{API}/enquiries", json=payload, timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["name"] == payload["name"]
        assert body["phone"] == payload["phone"]
        assert body["status"] == "new"
        assert "id" in body
        TestEnquiries.created_id = body["id"]

    def test_create_enquiry_minimal_fields(self):
        payload = {"name": "TEST_Min", "phone": "+919999999999"}
        r = requests.post(f"{API}/enquiries", json=payload, timeout=30)
        assert r.status_code == 200, r.text
        assert r.json()["name"] == "TEST_Min"

    def test_create_enquiry_missing_required(self):
        r = requests.post(f"{API}/enquiries", json={"name": "x"}, timeout=30)
        assert r.status_code == 422

    def test_list_enquiries_requires_auth(self):
        r = requests.get(f"{API}/enquiries", timeout=30)
        assert r.status_code in (401, 403)

    def test_list_enquiries_admin(self, admin_session):
        r = admin_session.get(f"{API}/enquiries", timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        assert isinstance(data, list)
        assert any(e["id"] == TestEnquiries.created_id for e in data)

    def test_patch_enquiry_status(self, admin_session):
        assert TestEnquiries.created_id, "create test must run first"
        r = admin_session.patch(f"{API}/enquiries/{TestEnquiries.created_id}",
                                json={"status": "contacted"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "contacted"
        # verify persistence
        r2 = admin_session.get(f"{API}/enquiries", timeout=30)
        match = [e for e in r2.json() if e["id"] == TestEnquiries.created_id]
        assert match and match[0]["status"] == "contacted"


# ---------- Inventory bulk-upload ----------
def _csv_bytes(rows, headers=None):
    headers = headers or ["name", "sku", "category", "price",
                          "stock", "low_stock_threshold"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=headers)
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode("utf-8")


def _xlsx_bytes(rows, headers=None):
    from openpyxl import Workbook
    headers = headers or ["name", "sku", "category", "price",
                          "stock", "low_stock_threshold"]
    wb = Workbook()
    ws = wb.active
    ws.append(headers)
    for r in rows:
        ws.append([r.get(h, "") for h in headers])
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


class TestInventoryBulkUpload:
    sku_csv = f"TEST-CSV-{uuid.uuid4().hex[:6].upper()}"
    sku_xlsx = f"TEST-XLSX-{uuid.uuid4().hex[:6].upper()}"

    def _upload(self, admin_token, content, filename):
        # multipart — build manual session without JSON content-type header
        headers = {"Authorization": f"Bearer {admin_token}"}
        files = {"file": (filename, content,
                          "text/csv" if filename.endswith(".csv")
                          else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
        return requests.post(f"{API}/inventory/bulk-upload",
                             headers=headers, files=files, timeout=60)

    def test_csv_upload_creates_items(self, admin_token):
        rows = [
            {"name": "TEST CSV Part 1", "sku": self.sku_csv,
             "category": "Test", "price": "100", "stock": "5",
             "low_stock_threshold": "2"},
            {"name": "TEST CSV Part 2", "sku": self.sku_csv + "B",
             "category": "Test", "price": "200", "stock": "10",
             "low_stock_threshold": "3"},
        ]
        r = self._upload(admin_token, _csv_bytes(rows), "items.csv")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["added"] == 2
        assert body["updated"] == 0
        assert body["errors"] == []
        assert body["total_rows"] == 2

    def test_csv_reupload_increments_stock(self, admin_token, admin_session):
        # initial stock from previous test = 5 for sku_csv
        rows = [{"name": "TEST CSV Part 1 Updated", "sku": self.sku_csv,
                 "category": "TestUpd", "price": "150", "stock": "7",
                 "low_stock_threshold": "4"}]
        r = self._upload(admin_token, _csv_bytes(rows), "items.csv")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["updated"] == 1
        assert body["added"] == 0
        # Verify stock incremented (5 + 7 = 12) and fields updated
        inv = admin_session.get(f"{API}/inventory").json()
        match = [i for i in inv if i["sku"] == self.sku_csv]
        assert match, "uploaded SKU not found"
        item = match[0]
        assert item["stock"] == 12, f"expected 12, got {item['stock']}"
        assert item["name"] == "TEST CSV Part 1 Updated"
        assert item["price"] == 150
        assert item["category"] == "TestUpd"

    def test_xlsx_upload(self, admin_token):
        rows = [{"name": "TEST XLSX Part", "sku": self.sku_xlsx,
                 "category": "Test", "price": "300", "stock": "4",
                 "low_stock_threshold": "1"}]
        r = self._upload(admin_token, _xlsx_bytes(rows), "items.xlsx")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["added"] == 1
        assert body["errors"] == []

    def test_missing_required_columns_reports_errors(self, admin_token):
        # Headers OK but rows missing stock + price → row-level errors
        headers = ["name", "sku", "category", "price", "stock"]
        rows = [
            {"name": "Bad Row", "sku": "TEST-BAD-1", "category": "x",
             "price": "", "stock": ""},
            {"name": "", "sku": "", "category": "", "price": "", "stock": ""},
        ]
        r = self._upload(admin_token, _csv_bytes(rows, headers), "bad.csv")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["added"] == 0
        assert len(body["errors"]) >= 1
        # Each error should have row + error
        for e in body["errors"]:
            assert "row" in e and "error" in e
            assert isinstance(e["row"], int)

    def test_unsupported_file_type(self, admin_token):
        r = self._upload(admin_token, b"hello", "items.txt")
        assert r.status_code == 400


# ---------- Bookings (car_make / car_model / mechanic_phone) ----------
class TestBookings:
    mechanic_phone = f"+9199{uuid.uuid4().int % 100000000:08d}"
    booking_id = None

    def test_seed_mechanic(self, admin_session):
        """Create a mechanic so auto-assign has someone to pick."""
        # Try to find existing mechanic
        users = admin_session.get(f"{API}/users").json()
        if not any(u.get("role") == "mechanic" for u in users):
            r = admin_session.post(f"{API}/admin/staff", json={
                "name": "TEST Mechanic",
                "phone": TestBookings.mechanic_phone,
                "role": "mechanic"
            })
            assert r.status_code == 200, r.text
            assert r.json()["role"] == "mechanic"
            assert r.json()["phone"] == TestBookings.mechanic_phone
        else:
            mech = next(u for u in users if u["role"] == "mechanic")
            TestBookings.mechanic_phone = mech.get("phone")

    def test_create_booking_with_car_fields(self, admin_session):
        payload = {
            "customer_name": "TEST_BookingCust",
            "customer_phone": f"+91900000{uuid.uuid4().int % 10000:04d}",
            "car_make": "Honda",
            "car_model": "City",
            "plate_number": f"KA01TEST{uuid.uuid4().hex[:3].upper()}",
            "service_type": "general",
            "notes": "test",
        }
        r = admin_session.post(f"{API}/bookings", json=payload)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["car_make"] == "Honda"
        assert body["car_model"] == "City"
        assert "bike_make" not in body
        assert "bike_model" not in body
        TestBookings.booking_id = body["id"]
        # auto-assign should have picked the mechanic and set phone
        assert body.get("mechanic_id"), "auto-assign did not pick a mechanic"
        assert body.get("mechanic_phone"), \
            f"mechanic_phone missing on booking: {body}"

    def test_get_booking_has_mechanic_phone(self, admin_session):
        assert TestBookings.booking_id
        r = admin_session.get(f"{API}/bookings/{TestBookings.booking_id}")
        assert r.status_code == 200, r.text
        b = r.json()
        assert b.get("mechanic_phone")
        assert b["car_make"] == "Honda"


# ---------- Inventory listing ----------
class TestInventoryListing:
    def test_inventory_has_seeded_car_part(self, admin_session):
        r = admin_session.get(f"{API}/inventory")
        assert r.status_code == 200, r.text
        items = r.json()
        skus = {i["sku"] for i in items}
        assert "OIL-CST-4L-5W30" in skus, \
            f"car-specific seed missing. Got SKUs: {sorted(skus)[:10]}..."
        # Make sure 2-wheeler SKUs are gone
        old_skus = {"OIL-CST-1L", "BRK-PAD-01", "FLT-AIR-01",
                    "SPK-NGK-01", "CHN-LUB-01", "TYR-90-17", "COL-500"}
        leaked = old_skus & skus
        assert not leaked, f"old 2-wheeler SKUs present: {leaked}"
