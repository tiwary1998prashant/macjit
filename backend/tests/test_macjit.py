"""MacJit Backend E2E Tests - full booking lifecycle, RBAC, inventory, admin stats, notifications, WS."""
import os
import asyncio
import json
from pathlib import Path

import pytest
import requests
import websockets
from dotenv import load_dotenv

# Load test environment variables from .env.test
test_env_file = Path(__file__).parent.parent / ".env.test"
if test_env_file.exists():
    load_dotenv(test_env_file, override=True)
else:
    # Fallback to example if .env.test doesn't exist
    load_dotenv(Path(__file__).parent.parent / ".env.test.example", override=True)

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')
if not BASE_URL:
    # fallback read frontend .env
    with open('/app/frontend/.env') as f:
        for line in f:
            if line.startswith('REACT_APP_BACKEND_URL='):
                BASE_URL = line.split('=', 1)[1].strip().rstrip('/')

API = f"{BASE_URL}/api"
WS_URL = BASE_URL.replace('https://', 'wss://').replace('http://', 'ws://') + '/api/ws'

CREDS = {
    "customer": "customer123",
    "customer2": "customer123",
    "reception": "reception123",
    "mechanic": "mechanic123",
    "mechanic2": "mechanic123",
    "tester": "tester123",
    "admin": "admin123",
}

# Shared state between tests
state = {}


def login(username):
    r = requests.post(f"{API}/auth/login", json={"username": username, "password": CREDS[username]})
    assert r.status_code == 200, f"login {username}: {r.status_code} {r.text}"
    data = r.json()
    return data["token"], data["user"]


def auth_hdr(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def tokens():
    t = {}
    users = {}
    for role in CREDS:
        tok, u = login(role)
        t[role] = tok
        users[role] = u
    state["tokens"] = t
    state["users"] = users
    return t


# ---------- AUTH ----------
class TestAuth:
    def test_login_success_all_roles(self, tokens):
        assert len(tokens) == 7
        for role, tok in tokens.items():
            assert isinstance(tok, str) and len(tok) > 20

    def test_login_invalid_password(self):
        r = requests.post(f"{API}/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

    def test_auth_me(self, tokens):
        r = requests.get(f"{API}/auth/me", headers=auth_hdr(tokens["admin"]))
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == "admin"
        assert data["username"] == "admin"
        assert "password_hash" not in data

    def test_auth_me_no_token(self):
        r = requests.get(f"{API}/auth/me")
        assert r.status_code == 401


# ---------- USERS / BAYS ----------
class TestMeta:
    def test_users_by_role_customer(self, tokens):
        r = requests.get(f"{API}/users/by-role/customer", headers=auth_hdr(tokens["reception"]))
        assert r.status_code == 200
        assert len(r.json()) >= 2

    def test_users_by_role_mechanic(self, tokens):
        r = requests.get(f"{API}/users/by-role/mechanic", headers=auth_hdr(tokens["reception"]))
        assert r.status_code == 200
        assert len(r.json()) >= 2

    def test_bays_count(self, tokens):
        r = requests.get(f"{API}/bays", headers=auth_hdr(tokens["mechanic"]))
        assert r.status_code == 200
        bays = r.json()
        assert len(bays) == 4


# ---------- INVENTORY ----------
class TestInventory:
    def test_list_inventory_seeded(self, tokens):
        r = requests.get(f"{API}/inventory", headers=auth_hdr(tokens["mechanic"]))
        assert r.status_code == 200
        items = r.json()
        assert len(items) >= 8
        state["inventory"] = items

    def test_alerts_structure(self, tokens):
        r = requests.get(f"{API}/inventory/alerts", headers=auth_hdr(tokens["admin"]))
        assert r.status_code == 200, r.text
        data = r.json()
        assert "out_of_stock" in data and "low_stock" in data and "fifo" in data
        # Spark Plug stock=0 -> out_of_stock; Air Filter stock=3 <=5 -> low_stock
        assert any("Spark Plug" in i["name"] for i in data["out_of_stock"])
        assert any("Air Filter" in i["name"] for i in data["low_stock"])
        # FIFO: two OIL-CST-1L SKUs, use the older one
        assert any(f["sku"] == "OIL-CST-1L" for f in data["fifo"])

    def test_alerts_forbidden_for_mechanic(self, tokens):
        r = requests.get(f"{API}/inventory/alerts", headers=auth_hdr(tokens["mechanic"]))
        assert r.status_code == 403

    def test_create_and_delete_inventory(self, tokens):
        payload = {"name": "TEST_Widget", "sku": "TEST-WGT-01", "category": "Test",
                   "price": 99.0, "stock": 10, "low_stock_threshold": 2}
        r = requests.post(f"{API}/inventory", json=payload, headers=auth_hdr(tokens["admin"]))
        assert r.status_code == 200, r.text
        item = r.json()
        assert item["name"] == "TEST_Widget"
        assert "id" in item
        # delete as admin
        d = requests.delete(f"{API}/inventory/{item['id']}", headers=auth_hdr(tokens["admin"]))
        assert d.status_code == 200

    def test_delete_inventory_forbidden_reception(self, tokens):
        # Create an item then try to delete as reception (admin-only)
        payload = {"name": "TEST_NoDelete", "sku": "TEST-ND-01", "category": "Test",
                   "price": 10, "stock": 1, "low_stock_threshold": 1}
        c = requests.post(f"{API}/inventory", json=payload, headers=auth_hdr(tokens["admin"]))
        iid = c.json()["id"]
        r = requests.delete(f"{API}/inventory/{iid}", headers=auth_hdr(tokens["reception"]))
        assert r.status_code == 403
        # cleanup
        requests.delete(f"{API}/inventory/{iid}", headers=auth_hdr(tokens["admin"]))


# ---------- BOOKING LIFECYCLE ----------
class TestBookingLifecycle:
    def test_customer_cannot_create_booking(self, tokens):
        cust_id = state["users"]["customer"]["id"]
        payload = {"customer_id": cust_id, "car_make": "Honda", "car_model": "CBR",
                   "plate_number": "TEST-RBAC", "service_type": "general", "notes": ""}
        r = requests.post(f"{API}/bookings", json=payload, headers=auth_hdr(tokens["customer"]))
        assert r.status_code == 403

    def test_reception_creates_booking(self, tokens):
        cust_id = state["users"]["customer"]["id"]
        payload = {"customer_id": cust_id, "car_make": "Honda", "car_model": "CBR",
                   "plate_number": "TEST-KA01-9999", "service_type": "full-service", "notes": "TEST"}
        r = requests.post(f"{API}/bookings", json=payload, headers=auth_hdr(tokens["reception"]))
        assert r.status_code == 200, r.text
        b = r.json()
        assert b["status"] == "BOOKED"
        assert b["customer_name"] == state["users"]["customer"]["name"]
        state["booking_id"] = b["id"]

    def test_notifications_created_on_booking(self, tokens):
        r = requests.get(f"{API}/notifications/me", headers=auth_hdr(tokens["customer"]))
        assert r.status_code == 200
        notifs = r.json()
        assert any(n.get("booking_id") == state["booking_id"] and n["event_type"] == "BOOKING_CREATED" for n in notifs)
        state["notif_id"] = next(n["id"] for n in notifs if n["booking_id"] == state["booking_id"])

    def test_mark_notification_read(self, tokens):
        r = requests.post(f"{API}/notifications/{state['notif_id']}/read", headers=auth_hdr(tokens["customer"]))
        assert r.status_code == 200

    def test_list_bookings_filters_by_role(self, tokens):
        # Customer sees only own
        rc = requests.get(f"{API}/bookings", headers=auth_hdr(tokens["customer"])).json()
        assert all(b["customer_id"] == state["users"]["customer"]["id"] for b in rc)
        # customer2 should NOT see customer1's booking
        rc2 = requests.get(f"{API}/bookings", headers=auth_hdr(tokens["customer2"])).json()
        assert not any(b["id"] == state["booking_id"] for b in rc2)

    def test_assign_mechanic_bay(self, tokens):
        mech_id = state["users"]["mechanic"]["id"]
        r = requests.patch(f"{API}/bookings/{state['booking_id']}/assign",
                           json={"mechanic_id": mech_id, "bay_id": "bay-1"},
                           headers=auth_hdr(tokens["reception"]))
        assert r.status_code == 200, r.text
        b = r.json()
        assert b["status"] == "ASSIGNED"
        assert b["mechanic_id"] == mech_id
        assert b["bay_id"] == "bay-1"

    def test_start_forbidden_other_mechanic(self, tokens):
        r = requests.post(f"{API}/bookings/{state['booking_id']}/start",
                          headers=auth_hdr(tokens["mechanic2"]))
        assert r.status_code == 403

    def test_start_service(self, tokens):
        r = requests.post(f"{API}/bookings/{state['booking_id']}/start",
                          headers=auth_hdr(tokens["mechanic"]))
        assert r.status_code == 200, r.text
        b = r.json()
        assert b["status"] == "IN_SERVICE"
        assert b["stream_active"] is True
        assert b["started_at"]

    def test_add_item_decrements_stock(self, tokens):
        inv = state["inventory"]
        # Pick Brake Pad (stock=8)
        bp = next(i for i in inv if i["sku"] == "BRK-PAD-01")
        before = bp["stock"]
        r = requests.post(f"{API}/bookings/{state['booking_id']}/items",
                          json={"inventory_id": bp["id"], "qty": 2},
                          headers=auth_hdr(tokens["mechanic"]))
        assert r.status_code == 200, r.text
        b = r.json()
        assert any(it["inventory_id"] == bp["id"] and it["qty"] == 2 for it in b["items"])
        # verify stock decremented
        inv_r = requests.get(f"{API}/inventory", headers=auth_hdr(tokens["admin"])).json()
        new_stock = next(i["stock"] for i in inv_r if i["id"] == bp["id"])
        assert new_stock == before - 2
        state["added_item_id"] = bp["id"]

    def test_add_item_insufficient_stock(self, tokens):
        # Spark plug has stock=0
        sp = next(i for i in state["inventory"] if i["sku"] == "SPK-NGK-01")
        r = requests.post(f"{API}/bookings/{state['booking_id']}/items",
                          json={"inventory_id": sp["id"], "qty": 1},
                          headers=auth_hdr(tokens["mechanic"]))
        assert r.status_code == 400

    def test_remove_item_restores_stock(self, tokens):
        bp_id = state["added_item_id"]
        inv_r = requests.get(f"{API}/inventory", headers=auth_hdr(tokens["admin"])).json()
        before = next(i["stock"] for i in inv_r if i["id"] == bp_id)
        r = requests.delete(f"{API}/bookings/{state['booking_id']}/items/{bp_id}",
                            headers=auth_hdr(tokens["mechanic"]))
        assert r.status_code == 200
        inv_r2 = requests.get(f"{API}/inventory", headers=auth_hdr(tokens["admin"])).json()
        after = next(i["stock"] for i in inv_r2 if i["id"] == bp_id)
        assert after == before + 2
        # re-add for billing
        requests.post(f"{API}/bookings/{state['booking_id']}/items",
                      json={"inventory_id": bp_id, "qty": 1},
                      headers=auth_hdr(tokens["mechanic"]))

    def test_request_approval(self, tokens):
        r = requests.post(f"{API}/bookings/{state['booking_id']}/request-approval",
                          json={"reason": "Need to replace fork seal", "extra_cost": 500},
                          headers=auth_hdr(tokens["mechanic"]))
        assert r.status_code == 200, r.text
        b = r.json()
        assert b["approval_pending"] is True
        assert b["extra_cost"] == 500

    def test_customer_approve(self, tokens):
        r = requests.post(f"{API}/bookings/{state['booking_id']}/approve",
                          headers=auth_hdr(tokens["customer"]))
        assert r.status_code == 200, r.text
        assert r.json()["approval_pending"] is False

    def test_other_customer_cannot_approve(self, tokens):
        r = requests.post(f"{API}/bookings/{state['booking_id']}/approve",
                          headers=auth_hdr(tokens["customer2"]))
        assert r.status_code == 403

    def test_finish_service(self, tokens):
        r = requests.post(f"{API}/bookings/{state['booking_id']}/finish",
                          headers=auth_hdr(tokens["mechanic"]))
        assert r.status_code == 200, r.text
        b = r.json()
        assert b["status"] == "READY_TO_TEST"
        assert b["stream_active"] is False

    def test_qa_done(self, tokens):
        r = requests.post(f"{API}/bookings/{state['booking_id']}/qa-done",
                          headers=auth_hdr(tokens["tester"]))
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "QA_DONE"

    def test_bill_generates_amount_and_link(self, tokens):
        r = requests.post(f"{API}/bookings/{state['booking_id']}/bill",
                          headers=auth_hdr(tokens["reception"]))
        assert r.status_code == 200, r.text
        b = r.json()
        assert b["status"] == "BILLED"
        # full-service base 1800 + BRK-PAD 850*1 + extra 500 = 3150
        assert b["bill_amount"] == 1800 + 850 + 500
        assert b["payment_link"] and "rzp.io" in b["payment_link"]

    def test_pay(self, tokens):
        r = requests.post(f"{API}/bookings/{state['booking_id']}/pay",
                          headers=auth_hdr(tokens["customer"]))
        assert r.status_code == 200, r.text
        b = r.json()
        assert b["status"] == "PAID"
        assert b["paid"] is True


# ---------- ADMIN STATS ----------
class TestAdmin:
    def test_admin_stats_shape(self, tokens):
        r = requests.get(f"{API}/admin/stats", headers=auth_hdr(tokens["admin"]))
        assert r.status_code == 200, r.text
        s = r.json()
        for k in ["today_serviced", "today_revenue", "active_bays", "total_bookings",
                  "by_status", "last_7_days", "low_stock_count", "out_of_stock_count"]:
            assert k in s
        assert len(s["last_7_days"]) == 7
        assert s["total_bookings"] >= 1
        # Our paid booking contributes to today_revenue
        assert s["today_serviced"] >= 1
        assert s["today_revenue"] >= 3150

    def test_stats_forbidden_for_customer(self, tokens):
        r = requests.get(f"{API}/admin/stats", headers=auth_hdr(tokens["customer"]))
        assert r.status_code == 403


# ---------- WEBSOCKET ----------
class TestWebSocket:
    def test_ws_connect_and_receive(self, tokens):
        async def run():
            uri = f"{WS_URL}/{tokens['admin']}"
            try:
                async with websockets.connect(uri, open_timeout=10) as ws:
                    first = await asyncio.wait_for(ws.recv(), timeout=5)
                    data = json.loads(first)
                    assert data["type"] == "connected"
                    # Trigger an event: create a booking via reception
                    cust_id = state["users"]["customer"]["id"]
                    payload = {"customer_id": cust_id, "car_make": "Yamaha", "car_model": "R15",
                               "plate_number": "TEST-WS-01", "service_type": "oil-change"}
                    requests.post(f"{API}/bookings", json=payload,
                                  headers=auth_hdr(tokens["reception"]))
                    # Expect event
                    msg = await asyncio.wait_for(ws.recv(), timeout=10)
                    ev = json.loads(msg)
                    assert ev.get("type") == "BOOKING_CREATED"
            except Exception as e:
                pytest.fail(f"WS test failed: {e}")
        asyncio.run(run())
