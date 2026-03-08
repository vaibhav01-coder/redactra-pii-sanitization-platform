from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import CaseFile, EventType, PiiEntity, User
from app.schemas import OverrideRequest
from app.services.audit_service import create_audit_log
from app.services.file_service import extract_text
from app.services.masking_service import compute_risk_score

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/{file_id}/override")
def override_entity(
    file_id: str,
    payload: OverrideRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    case = db.query(CaseFile).filter(CaseFile.id == file_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="File not found")

    entity = db.query(PiiEntity).filter(PiiEntity.id == payload.entity_id, PiiEntity.file_id == file_id).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    entity.is_false_positive = payload.is_false_positive
    active = db.query(PiiEntity).filter(PiiEntity.file_id == file_id, PiiEntity.is_false_positive.is_(False)).all()
    case.pii_count = len(active)

    text_len = 1
    sanitized_path = Path(case.sanitized_path)
    if sanitized_path.exists():
        try:
            text_len = max(1, len(extract_text(sanitized_path)))
        except Exception:
            text_len = max(1, len(sanitized_path.read_bytes()))

    fake_detections = [
        type("D", (), {"entity_type": e.entity_type, "start": e.char_start, "end": e.char_end}) for e in active
    ]
    case.risk_score = compute_risk_score(fake_detections, text_len)

    create_audit_log(
        db,
        event_type=EventType.false_positive_override,
        user_id=admin.id,
        file_id=file_id,
        metadata={"entity_id": entity.id, "false_positive": payload.is_false_positive},
    )
    db.commit()
    return {"message": "Override saved", "pii_count": case.pii_count, "risk_score": case.risk_score}

