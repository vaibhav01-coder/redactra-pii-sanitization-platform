from pathlib import Path

from sqlalchemy.orm import Session

from app.core.time import now_ist_naive
from app.database import SessionLocal
from app.models import CaseFile, EventType
from app.services.audit_service import create_audit_log
from app.services.supabase_storage import supabase_storage


class AutoDestructService:
    def run_once(self) -> int:
        db: Session = SessionLocal()
        deleted = 0
        try:
            expired = db.query(CaseFile).filter(CaseFile.expires_at < now_ist_naive()).all()
            for case in expired:
                if supabase_storage.enabled:
                    try:
                        supabase_storage.client.storage.from_("raw-files").remove([case.original_path])
                    except Exception:
                        pass
                    try:
                        supabase_storage.client.storage.from_("sanitized-files").remove([case.sanitized_path])
                    except Exception:
                        pass
                else:
                    Path(case.original_path).unlink(missing_ok=True)
                    Path(case.sanitized_path).unlink(missing_ok=True)

                create_audit_log(
                    db,
                    event_type=EventType.auto_deleted,
                    user_id=case.owner_id,
                    file_id=case.id,
                    metadata={"reason": "expires_at passed"},
                )
                db.delete(case)
                deleted += 1

            db.commit()
        finally:
            db.close()
        return deleted


auto_destruct_service = AutoDestructService()
