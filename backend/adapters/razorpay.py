"""Razorpay adapter for payment processing."""
import logging
from typing import Optional, Dict, Any, Tuple
from config import config

logger = logging.getLogger(__name__)

import hashlib
import hmac as _hmac

class RazorpayAdapter:
    enabled = bool(config.RAZORPAY_KEY_ID and config.RAZORPAY_KEY_SECRET)
    WEBHOOK_SECRET = config.RAZORPAY_WEBHOOK_SECRET

    @classmethod
    async def create_payment_link_full(cls, amount: float, ref_id: str, customer_phone: str = "",
                                        notes: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
        if not cls.enabled:
            raise Exception("Razorpay not configured. Check env variables.")

        try:
            import httpx

            # Ensure phone format
            if customer_phone and not customer_phone.startswith("+"):
                customer_phone = "+91" + customer_phone[-10:]

            payload = {
                "amount": int(amount * 100),
                "currency": "INR",
                "description": f"MacJit #{ref_id[:8]}",
                "customer": {"contact": customer_phone} if customer_phone else {},
                "notify": {"sms": True, "email": False},
                "notes": {**(notes or {}), "ref_id": ref_id},
            }

            async with httpx.AsyncClient(timeout=15) as cli:
                r = await cli.post(
                    "https://api.razorpay.com/v1/payment_links",
                    json=payload,
                    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET),
                )

                # 🔥 CRITICAL FIX
                if r.status_code >= 400:
                    logger.error(f"[RAZORPAY ERROR] {r.status_code} {r.text}")
                    raise Exception(f"Razorpay API failed: {r.text}")

                data = r.json()

                if not data.get("short_url"):
                    raise Exception(f"Invalid Razorpay response: {data}")

                return data["short_url"], data.get("id", "")

        except ImportError:
            logger.warning("httpx not installed")
            raise Exception("httpx not available")
        except Exception as e:
            logger.error(f"[RAZORPAY-EXCEPTION] {e}")
            raise Exception(f"Payment link generation failed: {str(e)}")