import io
import mimetypes
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import get_current_user
from app.models import CaseFile, EventType, PiiEntity, User, UserRole
from app.schemas import BulkDownloadRequest, CaseFileOut, CaseResultOut, PiiEntityOut
from app.services.audit_service import create_audit_log
from app.services.crypto_service import crypto_service
from app.services.supabase_storage import supabase_storage

router = APIRouter(prefix="/files", tags=["files"])


def _assert_case_access(case: CaseFile, user: User) -> None:
    if user.role == UserRole.admin:
        return
    if case.owner_id != user.id:
        raise HTTPException(status_code=404, detail="File not found")


def _load_sanitized_bytes(case: CaseFile) -> tuple[bytes, str]:
    filename = Path(case.sanitized_path).name
    if supabase_storage.enabled:
        data = supabase_storage.download_sanitized(case.sanitized_path)
        return data, filename

    path = Path(case.sanitized_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Sanitized file not found")
    return path.read_bytes(), filename


@router.get("/", response_model=list[CaseFileOut])
def list_files(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    query = db.query(CaseFile).order_by(CaseFile.created_at.desc())
    if user.role != UserRole.admin:
        query = query.filter(CaseFile.owner_id == user.id).filter(CaseFile.sanitized_path.is_not(None))
    return query.all()


@router.post("/bulk-download")
def bulk_download_sanitized(
    payload: BulkDownloadRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not payload.file_ids:
        raise HTTPException(status_code=400, detail="file_ids cannot be empty")

    buffer = io.BytesIO()
    used_names: set[str] = set()

    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_id in payload.file_ids:
            case = db.query(CaseFile).filter(CaseFile.id == file_id).first()
            if not case:
                raise HTTPException(status_code=404, detail=f"File not found: {file_id}")
            _assert_case_access(case, user)

            try:
                data, filename = _load_sanitized_bytes(case)
            except Exception as exc:
                raise HTTPException(status_code=404, detail=f"Sanitized file missing for: {file_id}") from exc

            arcname = filename
            if arcname in used_names:
                arcname = f"{Path(filename).stem}_{file_id[:8]}{Path(filename).suffix}"
            used_names.add(arcname)
            zf.writestr(arcname, data)

            create_audit_log(
                db,
                event_type=EventType.download,
                user_id=user.id,
                file_id=file_id,
                metadata={"target": "sanitized_bulk"},
            )

    db.commit()
    zip_bytes = buffer.getvalue()
    return StreamingResponse(
        iter([zip_bytes]),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="sanitized_files.zip"'},
    )


@router.get("/{file_id}/result", response_model=CaseResultOut)
def file_result(file_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    case = db.query(CaseFile).filter(CaseFile.id == file_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="File not found")
    _assert_case_access(case, user)

    entities = db.query(PiiEntity).filter(PiiEntity.file_id == file_id, PiiEntity.is_false_positive.is_(False)).all()
    if user.role != UserRole.admin:
        masked_entities = [
            PiiEntityOut(
                id=e.id,
                entity_type=e.entity_type,
                masked_value=e.masked_value,
                token_key=None,
                confidence=e.confidence,
                detection_layer=e.detection_layer,
                char_start=e.char_start,
                char_end=e.char_end,
            )
            for e in entities
        ]
        return CaseResultOut(file=case, entities=masked_entities)

    admin_entities = []
    for e in entities:
        try:
            orig = crypto_service.decrypt_text(e.original_value)
        except Exception:
            orig = "[decrypt failed]"
        admin_entities.append(
            PiiEntityOut(
                id=e.id,
                entity_type=e.entity_type,
                masked_value=e.masked_value,
                token_key=e.token_key,
                confidence=e.confidence,
                detection_layer=e.detection_layer,
                char_start=e.char_start,
                char_end=e.char_end,
                original_value=orig,
            )
        )
    return CaseResultOut(file=case, entities=admin_entities)


@router.get("/{file_id}/download")
def download_sanitized(file_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    case = db.query(CaseFile).filter(CaseFile.id == file_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="File not found")
    _assert_case_access(case, user)

    create_audit_log(db, event_type=EventType.download, user_id=user.id, file_id=file_id, metadata={"target": "sanitized"})
    db.commit()

    if supabase_storage.enabled:
        try:
            data = supabase_storage.download_sanitized(case.sanitized_path)
        except Exception as exc:
            raise HTTPException(status_code=404, detail="Sanitized file not found in storage") from exc

        filename = Path(case.sanitized_path).name
        media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        return StreamingResponse(
            iter([data]),
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    path = Path(case.sanitized_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Sanitized file not found")
    return FileResponse(path=path, filename=path.name)


@router.get("/{file_id}/original")
def download_original(file_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != UserRole.admin:
        create_audit_log(db, event_type=EventType.access_denied, user_id=user.id, file_id=file_id, metadata={"reason": "original_admin_only"})
        db.commit()
        raise HTTPException(status_code=404, detail="File not found")

    case = db.query(CaseFile).filter(CaseFile.id == file_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="File not found")

    if supabase_storage.enabled:
        try:
            encrypted_data = supabase_storage.download_raw(case.original_path)
        except Exception as exc:
            raise HTTPException(status_code=404, detail="Original file not found in storage") from exc
    else:
        path = Path(case.original_path)
        if not path.exists():
            raise HTTPException(status_code=404, detail="Original file not found")
        encrypted_data = path.read_bytes()

    try:
        data = crypto_service.decrypt_bytes(encrypted_data)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to decrypt original file") from exc

    create_audit_log(db, event_type=EventType.download, user_id=user.id, file_id=file_id, metadata={"target": "original"})
    db.commit()

    original_name = Path(case.original_path).name
    return StreamingResponse(
        iter([data]),
        media_type=mimetypes.guess_type(original_name)[0] or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{original_name}"'},
    )

