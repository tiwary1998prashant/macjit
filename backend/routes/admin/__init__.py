from .admin import router as admin_router
from .staff import router as staff_router
from .services import router as services_router

__all__ = [
    'admin_router',
    'staff_router',
    'services_router',
]
