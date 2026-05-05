"""Pydantic models for MacJit backend."""
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any

# ---------- Auth Models ----------
class LoginIn(BaseModel):
    username: Optional[str] = None
    phone: Optional[str] = None
    password: str

class UserOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    username: str
    name: str
    role: str
    phone: Optional[str] = None

# ---------- Booking Models ----------
class BookingCreate(BaseModel):
    customer_name: str
    customer_phone: str
    car_make: str
    car_model: str
    plate_number: str
    service_type: str
    notes: Optional[str] = ""

class AssignIn(BaseModel):
    mechanic_id: str
    bay_id: str

class ApprovalReq(BaseModel):
    reason: str
    extra_cost: float = 0.0

# ---------- Staff Models ----------
class StaffCreate(BaseModel):
    name: str
    phone: str
    role: str  # mechanic | reception | tester | shopkeeper | admin
    password: Optional[str] = None  # admin sets initial password; if blank, server generates one

# ---------- Pricing Models ----------
class PricingIn(BaseModel):
    service_type: str
    base_price: float

# ---------- Inventory Models ----------
class InventoryIn(BaseModel):
    name: str
    sku: str
    category: str
    price: float
    stock: int
    low_stock_threshold: int = 5
    stocked_at: Optional[str] = None
    expiry_at: Optional[str] = None

class BulkInventory(BaseModel):
    items: List[InventoryIn]

# ---------- Enquiry Models ----------
class EnquiryIn(BaseModel):
    name: str
    phone: str
    email: Optional[str] = ""
    car_make: Optional[str] = ""
    car_model: Optional[str] = ""
    service_interest: Optional[str] = ""
    message: Optional[str] = ""

# ---------- HR Models ----------
class LeaveIn(BaseModel):
    leave_type: str  # casual | earned | sick | unpaid
    start_date: str  # ISO date
    end_date: str
    reason: str = ""

class LeaveDecision(BaseModel):
    decision: str  # approved | rejected
    note: str = ""

class HolidayIn(BaseModel):
    date: str
    name: str
    type: str = "public"  # public | optional

class ProfileUpdate(BaseModel):
    monthly_salary: Optional[float] = None
    designation: Optional[str] = None
    join_date: Optional[str] = None
    leave_balance: Optional[Dict[str, int]] = None  # {casual: 12, earned: 15}

class BonusIn(BaseModel):
    user_id: str
    amount: float
    reason: str
    event_type: str = "bonus"  # bonus | extra_work | salary_credited

# ---------- Shop Models ----------
class ShopSaleLine(BaseModel):
    inventory_id: str
    qty: int = 1

class ShopSaleIn(BaseModel):
    customer_name: Optional[str] = ""
    customer_phone: Optional[str] = ""
    items: List[ShopSaleLine]
    payment_method: str = "cash"  # cash | razorpay
    fitting_charge: float = 0.0   # labour/fitting charge in ₹
    gst_percent: float = 0.0      # GST percentage, e.g. 18 for 18%

class RefundIn(BaseModel):
    sale_id: str
    reason: str
    items: Optional[List[ShopSaleLine]] = None  # if None → full refund of all sale items

# ---------- Service Models ----------
class ServiceIn(BaseModel):
    key: str            # unique slug, e.g. "oil-change"
    name: str           # display label, e.g. "Oil & Filter Change"
    duration_min: int   # estimated duration in minutes
    base_price: float   # base charge (₹)
    active: bool = True

class RefundDecision(BaseModel):
    decision: str  # approved | rejected
    note: str = ""