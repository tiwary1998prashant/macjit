from .admin import admin_router, staff_router, services_router
from .auth import auth_router
from .booking import bookings_router, progress_router
from .customer import customer_history_router, public_router
from .hr import hr_router
from .shop import inventory_router, payments_router, shop_router, digital_service_cards_router
from .core import notifications_router, ws_router, seeding  # side-effect import for startup seeding

admin_routes = [
    admin_router,
    staff_router,
    services_router,
]
auth_routes = [
    auth_router,
]
booking_routes = [
    bookings_router,
    progress_router,
]
customer_routes = [
    customer_history_router,
    public_router,
]
hr_routes = [
    hr_router,
]
shop_routes = [
    inventory_router,
    payments_router,
    shop_router,
    digital_service_cards_router,
]
core_routes = [
    notifications_router,
    ws_router,
]

routers = (
    admin_routes
    + auth_routes
    + booking_routes
    + customer_routes
    + hr_routes
    + shop_routes
    + core_routes
)
