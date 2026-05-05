"""Time and scheduling utilities."""
from datetime import datetime, timezone, timedelta
from config import config

def now_iso() -> str:
    """Get current timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()

def next_open_slot(after: datetime) -> datetime:
    """Snap a datetime forward to next working window (8am-6pm)."""
    dt = after
    if dt.hour < config.SHOP_OPEN_HOUR:
        dt = dt.replace(hour=config.SHOP_OPEN_HOUR, minute=0, second=0, microsecond=0)
    elif dt.hour >= config.SHOP_CLOSE_HOUR:
        dt = (dt + timedelta(days=1)).replace(hour=config.SHOP_OPEN_HOUR, minute=0, second=0, microsecond=0)
    return dt

def shift_within_hours(start: datetime, duration_min: int) -> tuple[datetime, datetime]:
    """If the slot crosses closing time, push start to next day."""
    start = next_open_slot(start)
    end = start + timedelta(minutes=duration_min)
    close_today = start.replace(hour=config.SHOP_CLOSE_HOUR, minute=0, second=0, microsecond=0)
    if end > close_today:
        start = (start + timedelta(days=1)).replace(hour=config.SHOP_OPEN_HOUR, minute=0, second=0, microsecond=0)
        end = start + timedelta(minutes=duration_min)
    return start, end