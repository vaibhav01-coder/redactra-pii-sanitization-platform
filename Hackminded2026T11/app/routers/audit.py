from pathlib import Path

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import get_current_user
from app.models import AuditLog, EventType, User, UserRole
from app.schemas import AuditLogOut
from app.services.audit_service import create_audit_log
from app.services.report_service import export_audit_pdf

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs", response_model=list[AuditLogOut])
def get_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if current_user.role != UserRole.admin:
        query = query.filter(AuditLog.user_id == current_user.id)

    logs = query.offset(skip).limit(limit).all()
    create_audit_log(db, event_type=EventType.admin_action, user_id=current_user.id, metadata={"action": "view_audit_logs"})
    db.commit()
    return logs


@router.get("/export")
def export_logs(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.admin:
        # Users can export only their own logs
        logs = db.query(AuditLog).filter(AuditLog.user_id == current_user.id).order_by(AuditLog.created_at.asc()).all()
        filename = "user_audit_log.pdf"
    else:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.asc()).all()
        filename = "chain_of_custody.pdf"

    output_path = Path("storage") / "exports" / filename
    export_audit_pdf(logs, output_path)

    create_audit_log(db, event_type=EventType.admin_action, user_id=current_user.id, metadata={"action": "export_audit_pdf"})
    db.commit()

    return FileResponse(path=output_path, filename=filename, media_type="application/pdf")
