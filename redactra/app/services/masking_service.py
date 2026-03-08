import uuid
from dataclasses import dataclass

from app.services.pii_engine import Detection


@dataclass
class MaskResult:
    sanitized_text: str
    replacements: list[tuple[Detection, str, str | None]]


SEVERITY_WEIGHTS = {
    "AADHAAR": 10,
    "PAN": 9,
    "BANK_ACCOUNT": 9,
    "CARD_NUMBER": 9,
    "PASSPORT": 8,
    "VOTER_ID": 8,
    "PHONE": 6,
    "EMAIL": 6,
    "NAME": 5,
    "ADDRESS": 5,
    "DOB": 4,
    "IP": 3,
    "BIOMETRIC": 9,
}


def _mask_value(value: str) -> str:
    if "@" in value:
        name, domain = value.split("@", 1)
        return f"{name[:1]}***@{domain[:1]}***"
    if len(value) <= 4:
        return "*" * len(value)
    return value[:1] + "*" * (len(value) - 2) + value[-1]


def sanitize_text(text: str, detections: list[Detection], mode: str) -> MaskResult:
    replacements: list[tuple[Detection, str, str | None]] = []
    chars = list(text)

    for det in sorted(detections, key=lambda d: d.start, reverse=True):
        token_key = None
        if mode == "redact":
            replacement = "[REDACTED]"
        elif mode == "mask":
            replacement = _mask_value(det.value)
        elif mode == "tokenize":
            token_key = f"TKN-{uuid.uuid4().hex[:10].upper()}"
            replacement = token_key
        else:
            replacement = "[REDACTED]"

        chars[det.start : det.end] = list(replacement)
        replacements.append((det, replacement, token_key))

    return MaskResult(sanitized_text="".join(chars), replacements=list(reversed(replacements)))


def compute_risk_score(detections: list[Detection], text_length: int) -> int:
    if not detections or text_length <= 0:
        return 0

    weighted = 0.0
    span_total = 0
    for det in detections:
        weighted += SEVERITY_WEIGHTS.get(det.entity_type, 4)
        span_total += max(1, det.end - det.start)

    density = min(1.0, span_total / max(1, text_length))
    score = min(100, int(weighted + density * 40))
    return score
