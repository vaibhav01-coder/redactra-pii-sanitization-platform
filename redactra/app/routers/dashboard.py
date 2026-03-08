from datetime import timedelta

from sqlalchemy import func
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.time import now_ist, now_ist_naive
from app.deps import get_current_user
from app.models import AuditLog, CaseFile, EventType, FileStatus, User, UserRole

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _file_query(db: Session, user: User):
    q = db.query(CaseFile)
    if user.role != UserRole.admin:
        q = q.filter(CaseFile.owner_id == user.id)
    return q


@router.get("/stats")
def stats(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    base = _file_query(db, user)
    total_files = base.count()
    subq = db.query(CaseFile.id).filter(CaseFile.owner_id == user.id) if user.role != UserRole.admin else db.query(CaseFile.id)
    total_entities = db.query(func.coalesce(func.sum(CaseFile.pii_count), 0)).filter(CaseFile.id.in_(subq)).scalar() or 0

    risk_bands = {
        "low": _file_query(db, user).filter(CaseFile.risk_score.between(0, 20)).count(),
        "moderate": _file_query(db, user).filter(CaseFile.risk_score.between(21, 50)).count(),
        "high": _file_query(db, user).filter(CaseFile.risk_score.between(51, 80)).count(),
        "critical": _file_query(db, user).filter(CaseFile.risk_score.between(81, 100)).count(),
    }
    flagged = _file_query(db, user).filter(CaseFile.status == FileStatus.flagged).count()
    now = now_ist_naive()
    hour_later = now + timedelta(hours=1)
    expiring_soon = _file_query(db, user).filter(
        CaseFile.expires_at <= hour_later, CaseFile.expires_at > now
    ).count()

    activity_query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if user.role != UserRole.admin:
        activity_query = activity_query.filter(AuditLog.user_id == user.id)
    activity_query = activity_query.limit(20)
    recent_activity = activity_query.all()

    auto_deleted_today = 0
    if user.role == UserRole.admin:
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        auto_deleted_today = db.query(AuditLog).filter(
            AuditLog.event_type == EventType.auto_deleted,
            AuditLog.created_at >= day_start,
        ).count()

    return {
        "total_files": total_files,
        "total_entities": int(total_entities),
        "risk_distribution": risk_bands,
        "flagged_count": flagged,
        "expiring_soon": expiring_soon,
        "auto_deleted_today": auto_deleted_today,
        "recent_activity": [
            {
                "event_type": item.event_type.value,
                "file_id": item.file_id,
                "user_id": item.user_id,
                "created_at": item.created_at.isoformat(),
            }
            for item in recent_activity
        ],
    }
