from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import CaseFile, EventType, PiiEntity, User
from app.schemas import DetokenizeRequest, DetokenizeResponse
from app.services.audit_service import create_audit_log
from app.services.crypto_service import crypto_service

router = APIRouter(prefix="/tokens", tags=["tokens"])


@router.get("/")
def list_tokens(
    file_id: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    query = db.query(PiiEntity).filter(PiiEntity.token_key.is_not(None))
    if file_id:
        query = query.filter(PiiEntity.file_id == file_id)
    tokens = query.order_by(PiiEntity.file_id).offset(skip).limit(limit).all()
    create_audit_log(db, event_type=EventType.admin_action, user_id=admin.id, metadata={"action": "list_tokens"})
    db.commit()
    result = []
    for t in tokens:
        case = db.query(CaseFile).filter(CaseFile.id == t.file_id).first()
        result.append({
            "id": t.id,
            "token_key": t.token_key,
            "entity_type": t.entity_type,
            "file_id": t.file_id,
            "uploaded_by": case.uploaded_by if case else None,
            "created_at": case.created_at.isoformat() if case else None,
        })
    return result


@router.post("/detokenize", response_model=DetokenizeResponse)
def detokenize(
    payload: DetokenizeRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    entity = db.query(PiiEntity).filter(PiiEntity.token_key == payload.token_key).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Token not found")

    original = crypto_service.decrypt_text(entity.original_value)
    create_audit_log(
        db,
        event_type=EventType.token_restored,
        user_id=admin.id,
        file_id=entity.file_id,
        metadata={"token_key": payload.token_key},
    )
    db.commit()
    return DetokenizeResponse(token_key=payload.token_key, original_value=original)

