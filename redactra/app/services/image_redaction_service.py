from pathlib import Path

from app.services.file_service import OcrToken
from app.services.pii_engine import Detection


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _bbox_for_detection(det: Detection, tokens: list[OcrToken]) -> tuple[int, int, int, int] | None:
    matched = [t for t in tokens if _overlaps(det.start, det.end, t.start, t.end)]
    if not matched:
        return None

    left = min(t.left for t in matched)
    top = min(t.top for t in matched)
    right = max(t.left + t.width for t in matched)
    bottom = max(t.top + t.height for t in matched)
    return left, top, right, bottom


def redact_image_regions(
    *,
    image_path: Path,
    output_path: Path,
    detections: list[Detection],
    ocr_tokens: list[OcrToken],
    masking_mode: str,
) -> None:
    try:
        from PIL import Image, ImageDraw, ImageFilter
    except Exception as exc:
        raise RuntimeError("Pillow is required for image redaction") from exc

    img = Image.open(image_path).convert("RGB")
    draw = ImageDraw.Draw(img)

    for det in detections:
        bbox = _bbox_for_detection(det, ocr_tokens)
        if not bbox:
            continue

        left, top, right, bottom = bbox
        pad = 2
        left = max(0, left - pad)
        top = max(0, top - pad)
        right = min(img.width, right + pad)
        bottom = min(img.height, bottom + pad)

        # For images: mask mode -> blur, redact/tokenize -> solid black box.
        if masking_mode == "mask":
            region = img.crop((left, top, right, bottom))
            img.paste(region.filter(ImageFilter.GaussianBlur(radius=8)), (left, top, right, bottom))
        else:
            draw.rectangle((left, top, right, bottom), fill="black")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(output_path)
