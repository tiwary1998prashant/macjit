from .inventory import router as inventory_router
from .payments import router as payments_router
from .shop import router as shop_router
from .digital_service_cards import router as digital_service_cards_router

__all__ = [
    'inventory_router',
    'payments_router',
    'shop_router',
    'digital_service_cards_router',
]
