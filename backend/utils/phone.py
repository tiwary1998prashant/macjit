def _normalize_phone(p: str) -> str:
    """Normalise Indian phone numbers to a consistent +91XXXXXXXXXX form.

    Accepts raw 10-digit numbers, 12-digit numbers starting with 91, and
    already-qualified +91 values. Preserves leading plus when provided.
    """
    if not p:
        return ""
    value = str(p).strip()
    if not value:
        return ""
    digits = "".join(ch for ch in value if ch.isdigit())
    if value.startswith("+"):
        if len(digits) == 10:
            return "+91" + digits
        if len(digits) == 12 and digits.startswith("91"):
            return "+" + digits
        return "+" + digits if digits else ""
    if len(digits) == 10:
        return "+91" + digits
    if len(digits) == 12 and digits.startswith("91"):
        return "+" + digits
    if len(digits) > 10:
        return "+91" + digits[-10:]
    return digits
