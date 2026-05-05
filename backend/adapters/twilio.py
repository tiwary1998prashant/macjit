"""Twilio adapter for SMS and WhatsApp messaging."""
import logging
from typing import Optional
from config import config

logger = logging.getLogger(__name__)

class TwilioAdapter:
    enabled = bool(config.TWILIO_ACCOUNT_SID and config.TWILIO_AUTH_TOKEN)

    @classmethod
    async def _post(cls, body_data: dict):
        try:
            import httpx
            sid = config.TWILIO_ACCOUNT_SID
            tok = config.TWILIO_AUTH_TOKEN
            url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
            async with httpx.AsyncClient(timeout=10) as cli:
                r = await cli.post(url, data=body_data, auth=(sid, tok))
                return r.status_code, r.text
        except ImportError:
            logger.warning("httpx not installed")
            return 500, "httpx not available"

    @classmethod
    async def send_whatsapp(cls, to: str, body: str):
        if cls.enabled:
            try:
                from_num = config.TWILIO_WHATSAPP_FROM
                if not from_num.startswith("whatsapp:"):
                    from_num = "whatsapp:" + from_num
                code, body_resp = await cls._post({"From": from_num, "To": f"whatsapp:{to}", "Body": body})
                logger.info(f"[TWILIO-WA->{to}] {code} {body_resp[:200] if code >= 400 else ''}")
            except Exception as e:
                logger.error(f"[TWILIO-WA-ERR] {e}")
        else:
            logger.info(f"[TWILIO-WA-MOCK->{to}] {body[:80]}")

    @classmethod
    async def send_sms(cls, to: str, body: str):
        if not cls.enabled:
            logger.warning("Twilio not configured")
            return

        try:
            import httpx

            if not to.startswith("+"):
                to = "+91" + to[-10:]

            from_num = config.TWILIO_SMS_FROM

            async with httpx.AsyncClient(timeout=10) as cli:
                r = await cli.post(
                    f"https://api.twilio.com/2010-04-01/Accounts/{config.TWILIO_ACCOUNT_SID}/Messages.json",
                    data={"From": from_num, "To": to, "Body": body},
                    auth=(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN),
                )

                if r.status_code >= 400:
                    logger.error(f"[TWILIO ERROR] {r.status_code} {r.text}")
                else:
                    logger.info(f"[SMS SENT] {to}")

        except Exception as e:
            logger.error(f"[TWILIO EXCEPTION] {e}")