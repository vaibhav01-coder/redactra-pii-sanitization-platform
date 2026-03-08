import re
from dataclasses import dataclass


@dataclass
class Detection:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float
    layer: str


@dataclass
class SkippedEntity:
    entity_type: str
    value: str
    start: int
    end: int
    reason: str


CONTEXT_ANCHOR_MAP: dict[str, list[str]] = {
    "AADHAAR": ["aadhaar", "aadhar", "uid", "uidai", "unique id"],
    "PAN": ["pan", "permanent account", "income tax", "pan card"],
    "PHONE": ["phone", "mobile", "contact", "call", "whatsapp", "tel"],
    "BANK_ACCOUNT": ["account", "acct", "bank", "savings", "current", "ifsc"],
    "CARD_NUMBER": ["card", "credit", "debit", "visa", "mastercard", "cvv", "expiry"],
    "PASSPORT": ["passport", "travel document", "issued by"],
    "VOTER_ID": ["voter", "epic", "election commission"],
    "IFSC": ["ifsc", "branch code", "rtgs", "neft", "imps"],
    "IP": ["ip", "address", "host", "server", "device", "source ip"],
    "DOB": ["dob", "date of birth", "born", "birth date", "age"],
    "NAME": ["name", "full name", "applicant", "holder", "customer"],
    "BIOMETRIC": ["fingerprint", "face_template", "face_id", "retina", "biometric", "iris_scan", "voiceprint"],
}

SELF_ANCHORED = {"EMAIL", "BIOMETRIC"}

REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AADHAAR", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
    ("PAN", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("PHONE", re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("UPI", re.compile(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b")),
    ("IFSC", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")),
    ("BANK_ACCOUNT", re.compile(r"\b\d{9,18}\b")),
    ("CARD_NUMBER", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("PASSPORT", re.compile(r"\b[A-Z][0-9]{7}\b")),
    ("VOTER_ID", re.compile(r"\b[A-Z]{3}[0-9]{7}\b")),
    (
        "BIOMETRIC",
        re.compile(
            r"\b(fingerprint|thumbprint|iris(?:\s+scan)?|retina(?:\s+scan)?|face\s*id|facial\s+recognition|voice\s*print|biometric(?:\s+template|\s+data)?|dna\s+profile|fp[_-]?hash[_-]?[a-f0-9]{8,64}|face[_-]?tmp[_-]?[a-z0-9]{6,32}|retina[_-]?[a-z0-9]{6,32}|(android|ios)[_-]?[a-f0-9]{8,32})\b",
            re.IGNORECASE,
        ),
    ),
]


def _is_contextually_valid(
    text: str,
    match_start: int,
    match_end: int,
    entity_type: str,
    base_confidence: float,
    context_hints: list[str] | None,
) -> tuple[bool, float]:
    if entity_type in SELF_ANCHORED:
        return True, base_confidence

    window_start = max(0, match_start - 100)
    window_end = min(len(text), match_end + 100)
    context = text[window_start:window_end].lower()
    extra_context = " ".join(context_hints or []).lower()

    keywords = CONTEXT_ANCHOR_MAP.get(entity_type, [])
    matched_keywords = [kw for kw in keywords if kw in context or kw in extra_context]
    if not matched_keywords:
        return False, 0.0

    confidence_boost = min(0.1 * len(matched_keywords), 0.3)
    return True, min(1.0, base_confidence + confidence_boost)


def _regex_detect(text: str, context_hints: list[str] | None) -> tuple[list[Detection], list[SkippedEntity]]:
    found: list[Detection] = []
    skipped: list[SkippedEntity] = []

    for entity_type, pattern in REGEX_PATTERNS:
        for match in pattern.finditer(text):
            valid, confidence = _is_contextually_valid(
                text,
                match.start(),
                match.end(),
                entity_type,
                1.0,
                context_hints,
            )
            if not valid:
                skipped.append(
                    SkippedEntity(
                        entity_type=entity_type,
                        value=match.group(0),
                        start=match.start(),
                        end=match.end(),
                        reason="Pattern matched but no context anchor within +/-100 chars",
                    )
                )
                continue

            found.append(
                Detection(
                    entity_type=entity_type,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    layer="regex",
                )
            )
    return found, skipped


def _spacy_detect(text: str, context_hints: list[str] | None) -> tuple[list[Detection], list[SkippedEntity]]:
    try:
        import spacy  # type: ignore
    except Exception:
        return [], []

    try:
        nlp = spacy.load("en_core_web_sm")
    except Exception:
        return [], []

    mapped = {
        "PERSON": "NAME",
        "ORG": "ORGANIZATION",
        "GPE": "ADDRESS",
        "LOC": "ADDRESS",
        "DATE": "DOB",
    }
    out: list[Detection] = []
    skipped: list[SkippedEntity] = []
    doc = nlp(text)
    for ent in doc.ents:
        entity_type = mapped.get(ent.label_)
        if not entity_type:
            continue

        valid, confidence = _is_contextually_valid(
            text,
            ent.start_char,
            ent.end_char,
            entity_type,
            0.75,
            context_hints,
        )
        if not valid:
            skipped.append(
                SkippedEntity(
                    entity_type=entity_type,
                    value=ent.text,
                    start=ent.start_char,
                    end=ent.end_char,
                    reason="NER entity skipped due to missing context anchor",
                )
            )
            continue

        out.append(
            Detection(
                entity_type=entity_type,
                value=ent.text,
                start=ent.start_char,
                end=ent.end_char,
                confidence=confidence,
                layer="spacy",
            )
        )
    return out, skipped


def _presidio_detect(text: str, context_hints: list[str] | None) -> tuple[list[Detection], list[SkippedEntity]]:
    try:
        from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer  # type: ignore
    except Exception:
        return [], []

    try:
        analyzer = AnalyzerEngine()
        biometric_patterns = [
            Pattern("FINGERPRINT_HASH", r"\bfp[_-]?hash[_-]?[a-f0-9]{8,64}\b", 0.95),
            Pattern("FACE_TEMPLATE", r"\bface[_-]?tmp[_-]?[a-z0-9]{6,32}\b", 0.95),
            Pattern("RETINA_SCAN", r"\bretina[_-]?[a-z0-9]{6,32}\b", 0.90),
            Pattern("DEVICE_BIOMETRIC", r"\b(android|ios)[_-]?[a-f0-9]{8,32}\b", 0.85),
        ]
        biometric_recognizer = PatternRecognizer(supported_entity="BIOMETRIC", patterns=biometric_patterns)
        analyzer.registry.add_recognizer(biometric_recognizer)
        results = analyzer.analyze(text=text, language="en")
    except Exception:
        return [], []

    mapped = {
        "PHONE_NUMBER": "PHONE",
        "EMAIL_ADDRESS": "EMAIL",
        "PERSON": "NAME",
        "IP_ADDRESS": "IP",
        "LOCATION": "ADDRESS",
        "CREDIT_CARD": "CARD_NUMBER",
        "DATE_TIME": "DOB",
    }
    out: list[Detection] = []
    skipped: list[SkippedEntity] = []
    for res in results:
        entity_type = mapped.get(res.entity_type, res.entity_type)
        value = text[res.start : res.end]
        valid, confidence = _is_contextually_valid(text, res.start, res.end, entity_type, float(res.score), context_hints)
        if not valid:
            skipped.append(
                SkippedEntity(
                    entity_type=entity_type,
                    value=value,
                    start=res.start,
                    end=res.end,
                    reason="Presidio entity skipped due to missing context anchor",
                )
            )
            continue

        out.append(
            Detection(
                entity_type=entity_type,
                value=value,
                start=res.start,
                end=res.end,
                confidence=confidence,
                layer="presidio",
            )
        )
    return out, skipped


def _dedupe(detections: list[Detection]) -> list[Detection]:
    best: dict[tuple[int, int, str], Detection] = {}
    for det in detections:
        key = (det.start, det.end, det.entity_type)
        if key not in best or det.confidence > best[key].confidence:
            best[key] = det
    return sorted(best.values(), key=lambda d: (d.start, d.end))


def detect_pii_with_context(text: str, context_hints: list[str] | None = None) -> tuple[list[Detection], list[SkippedEntity]]:
    detections: list[Detection] = []
    skipped: list[SkippedEntity] = []

    regex_found, regex_skipped = _regex_detect(text, context_hints)
    detections.extend(regex_found)
    skipped.extend(regex_skipped)

    spacy_found, spacy_skipped = _spacy_detect(text, context_hints)
    detections.extend(spacy_found)
    skipped.extend(spacy_skipped)

    presidio_found, presidio_skipped = _presidio_detect(text, context_hints)
    detections.extend(presidio_found)
    skipped.extend(presidio_skipped)

    return _dedupe(detections), skipped


def detect_pii(text: str) -> list[Detection]:
    detections, _ = detect_pii_with_context(text, None)
    return detections
