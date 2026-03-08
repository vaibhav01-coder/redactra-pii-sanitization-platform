import hashlib
import io
import mimetypes
import uuid
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from app.core.time import now_ist, now_ist_naive
from app.core.config import settings
from app.database import get_db
from app.deps import get_current_user
from app.models import AuditLog, CaseBatch, CaseFile, EventType, FileStatus, HoneypotStrike, PiiEntity, ScanStatus, User, UserRole
from app.services.audit_service import create_audit_log
from app.services.crypto_service import crypto_service
from app.services.file_service import (
    IMAGE_TYPES,
    SUPPORTED_TYPES,
    ensure_storage_dirs,
    extract_context_hints,
    extract_image_text_with_tokens,
    extract_text,
    write_sanitized_xlsx,
    strip_exif_if_image,
    validate_file_size,
    validate_magic_bytes,
    write_sanitized_output,
)
from app.services.image_redaction_service import redact_image_regions
from app.services.masking_service import compute_risk_score, sanitize_text
from app.services.pii_engine import detect_pii_with_context
from app.services.security_sweep_service import malware_scan_service
from app.services.supabase_storage import supabase_storage

router = APIRouter(prefix="/upload", tags=["upload"])


def _build_storage_paths(original_filename: str) -> tuple[Path, Path, str, str, str, str]:
    filename = Path(original_filename).name
    extension = Path(filename).suffix.lower()
    if extension == "":
        raise HTTPException(status_code=400, detail=f"File extension is required: {filename}")
    if extension not in SUPPORTED_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {extension}")

    base = Path(filename).stem.replace(" ", "_")
    uid = uuid.uuid4().hex[:8]
    raw_name = f"{base}_{uid}{extension}"
    sealed_name = f"{base}_{uid}_sealed{extension}"

    raw_path = settings.raw_storage_path / raw_name
    sealed_path = settings.sanitized_storage_path / sealed_name
    file_type = extension.lstrip(".")
    return raw_path, sealed_path, raw_name, sealed_name, file_type, extension


def _record_honeypot_strike(db: Session, user: User, request: Request) -> int:
    strike = db.query(HoneypotStrike).filter(HoneypotStrike.user_id == user.id).first()
    if not strike:
        strike = HoneypotStrike(user_id=user.id, strike_count=0)
        db.add(strike)
        db.flush()

    strike.strike_count += 1
    strike.last_triggered_at = now_ist()

    create_audit_log(
        db,
        event_type=EventType.bot_detected,
        user_id=user.id,
        metadata={
            "ip": request.client.host if request.client else "",
            "user_agent": request.headers.get("user-agent", ""),
            "strike_count": strike.strike_count,
        },
    )

    if strike.strike_count >= 3 and user.is_active:
        user.is_active = False
        create_audit_log(
            db,
            event_type=EventType.user_suspended,
            user_id=user.id,
            metadata={"reason": "honeypot_limit", "strike_count": strike.strike_count},
        )

    db.commit()
    return strike.strike_count


def _bot_guard(db: Session, user: User, bureau_field: str, request: Request) -> None:
    if bureau_field != "":
        strikes = _record_honeypot_strike(db, user, request)
        raise HTTPException(status_code=422, detail=f"Invalid submission (strike {strikes})")


def _enforce_upload_rate_limit(db: Session, user: User, max_uploads_per_hour: int = 20) -> None:
    one_hour_ago = now_ist() - timedelta(hours=1)
    count = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == user.id,
            AuditLog.created_at >= one_hour_ago,
            AuditLog.event_type.in_([EventType.upload, EventType.file_flagged, EventType.duplicate_detected]),
        )
        .count()
    )

    if count >= max_uploads_per_hour:
        create_audit_log(
            db,
            event_type=EventType.access_denied,
            user_id=user.id,
            metadata={"reason": "upload_rate_limit", "limit": max_uploads_per_hour, "window": "1h"},
        )
        db.commit()
        raise HTTPException(status_code=429, detail="Upload rate limit exceeded (20/hour)")


def _process_file(
    *,
    db: Session,
    user: User,
    local_path: Path,
    sealed_path: Path,
    file_type: str,
    masking_mode: str,
    raw_ref: str,
    sealed_ref: str,
    file_hash: str,
    scan_status: ScanStatus,
    vt_report: dict,
    exif_stripped: bool,
    batch_id: str | None,
) -> CaseFile:
    case = CaseFile(
        original_path=raw_ref,
        sanitized_path=sealed_ref,
        file_type=file_type,
        status=FileStatus.scanning,
        scan_status=scan_status,
        uploaded_by=user.id,
        owner_id=user.id,
        batch_id=batch_id,
        file_hash=file_hash,
        vt_report=vt_report,
        exif_stripped=exif_stripped,
    )
    db.add(case)
    db.flush()

    create_audit_log(db, event_type=EventType.upload, user_id=user.id, file_id=case.id, metadata={"path": raw_ref})
    create_audit_log(db, event_type=EventType.scan_start, user_id=user.id, file_id=case.id, metadata={"masking_mode": masking_mode})

    is_image = local_path.suffix.lower() in IMAGE_TYPES
    context_hints: list[str] = []
    ocr_tokens = []

    if is_image:
        text, ocr_tokens = extract_image_text_with_tokens(local_path)
    else:
        text = extract_text(local_path)
        context_hints = extract_context_hints(local_path)

    detections, skipped = detect_pii_with_context(text, context_hints)
    for skipped_entity in skipped[:100]:
        create_audit_log(
            db,
            event_type=EventType.context_skip,
            user_id=user.id,
            file_id=case.id,
            metadata={
                "entity_type": skipped_entity.entity_type,
                "value": skipped_entity.value,
                "reason": skipped_entity.reason,
                "start": skipped_entity.start,
                "end": skipped_entity.end,
            },
        )

    mask_result = sanitize_text(text, detections, masking_mode)

    if is_image:
        redact_image_regions(
            image_path=local_path,
            output_path=sealed_path,
            detections=detections,
            ocr_tokens=ocr_tokens,
            masking_mode=masking_mode,
        )
    else:
        if local_path.suffix.lower() == ".xlsx":
            write_sanitized_xlsx(template_path=local_path, output_path=sealed_path, sanitized_text=mask_result.sanitized_text)
        else:
            write_sanitized_output(sealed_path, mask_result.sanitized_text)

    entities = []
    for det, masked, token_key in mask_result.replacements:
        entities.append(
            PiiEntity(
                file_id=case.id,
                entity_type=det.entity_type,
                original_value=crypto_service.encrypt_text(det.value),
                masked_value=masked,
                token_key=token_key,
                confidence=det.confidence,
                detection_layer=det.layer,
                char_start=det.start,
                char_end=det.end,
            )
        )
    db.add_all(entities)

    plain_original_bytes = local_path.read_bytes()
    encrypted_original_bytes = crypto_service.encrypt_bytes(plain_original_bytes)
    sealed_bytes = sealed_path.read_bytes()

    if supabase_storage.enabled:
        original_ct = mimetypes.guess_type(local_path.name)[0] or "application/octet-stream"
        sealed_ct = mimetypes.guess_type(sealed_path.name)[0] or "application/octet-stream"
        supabase_storage.upload_raw(raw_ref, encrypted_original_bytes, original_ct)
        supabase_storage.upload_sanitized(sealed_ref, sealed_bytes, sealed_ct)

        local_path.unlink(missing_ok=True)
        sealed_path.unlink(missing_ok=True)
    else:
        local_path.write_bytes(encrypted_original_bytes)

    case.pii_count = len(entities)
    case.risk_score = compute_risk_score(detections, len(text))
    case.status = FileStatus.sanitized

    create_audit_log(
        db,
        event_type=EventType.scan_complete,
        user_id=user.id,
        file_id=case.id,
        metadata={"pii_count": case.pii_count, "risk_score": case.risk_score},
    )
    create_audit_log(
        db,
        event_type=EventType.masked,
        user_id=user.id,
        file_id=case.id,
        metadata={"mode": masking_mode},
    )
    create_audit_log(
        db,
        event_type=EventType.file_sanitized,
        user_id=user.id,
        file_id=case.id,
        metadata={"mode": masking_mode, "pii_count": case.pii_count},
    )
    db.commit()
    db.refresh(case)
    return case


async def _process_upload_file(
    *,
    db: Session,
    user: User,
    upload: UploadFile,
    masking_mode: str,
    batch_id: str | None,
) -> dict:
    raw_path, sealed_path, raw_name, sealed_name, file_type, extension = _build_storage_paths(upload.filename)
    raw_ref = raw_name if supabase_storage.enabled else str(raw_path)
    sealed_ref = sealed_name if supabase_storage.enabled else str(sealed_path)

    file_bytes = await upload.read()
    validate_file_size(extension, len(file_bytes))

    try:
        validate_magic_bytes(file_bytes, extension)
    except ValueError as exc:
        create_audit_log(db, event_type=EventType.magic_byte_mismatch, user_id=user.id, metadata={"file": upload.filename, "reason": str(exc)})
        db.commit()
        raise

    file_bytes, exif_removed, exif_count = strip_exif_if_image(file_bytes, extension)
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    existing = (
        db.query(CaseFile)
        .filter(CaseFile.file_hash == file_hash, CaseFile.owner_id == user.id, CaseFile.expires_at > now_ist_naive())
        .first()
    )
    if existing:
        create_audit_log(db, event_type=EventType.duplicate_detected, user_id=user.id, file_id=existing.id, metadata={"file_hash": file_hash})
        db.commit()
        return {"duplicate": True, "file_id": existing.id, "message": "Case already exists and is active"}

    sweep = malware_scan_service.check_hash(file_hash)
    if sweep.status == "QUARANTINED":
        quarantined_case = CaseFile(
            original_path="",
            sanitized_path="",
            file_type=file_type,
            status=FileStatus.flagged,
            scan_status=ScanStatus.quarantined,
            uploaded_by=user.id,
            owner_id=user.id,
            batch_id=batch_id,
            file_hash=file_hash,
            vt_report=sweep.report,
            exif_stripped=exif_removed,
        )
        db.add(quarantined_case)
        db.flush()
        create_audit_log(
            db,
            event_type=EventType.file_flagged,
            user_id=user.id,
            file_id=quarantined_case.id,
            metadata={"file_hash": file_hash, "vt_report": sweep.report},
        )
        db.commit()
        return {"file": upload.filename, "status": FileStatus.flagged.value, "file_id": quarantined_case.id}

    scan_status = ScanStatus.pending if sweep.status == "PENDING" else ScanStatus.passed
    if scan_status == ScanStatus.passed:
        create_audit_log(db, event_type=EventType.malware_scan_passed, user_id=user.id, metadata={"file_hash": file_hash, "vt": sweep.report})
    else:
        create_audit_log(db, event_type=EventType.malware_scan_failed, user_id=user.id, metadata={"file_hash": file_hash, "vt": sweep.report})

    if exif_removed:
        create_audit_log(db, event_type=EventType.exif_stripped, user_id=user.id, metadata={"file": upload.filename, "exif_fields_removed": exif_count})

    raw_path.write_bytes(file_bytes)

    case = _process_file(
        db=db,
        user=user,
        local_path=raw_path,
        sealed_path=sealed_path,
        file_type=file_type,
        masking_mode=masking_mode,
        raw_ref=raw_ref,
        sealed_ref=sealed_ref,
        file_hash=file_hash,
        scan_status=scan_status,
        vt_report=sweep.report,
        exif_stripped=exif_removed,
        batch_id=batch_id,
    )
    return {"file": Path(upload.filename).name, "file_id": case.id, "status": case.status.value, "risk_score": case.risk_score, "pii_count": case.pii_count}


async def _process_zip_archive_bytes(
    *,
    db: Session,
    user: User,
    archive_name: str,
    archive_bytes: bytes,
    masking_mode: str,
    batch_id: str | None,
) -> list[dict]:
    results: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue

            member_path = Path(member.filename)
            if ".." in member_path.parts:
                results.append({"file": member.filename, "status": "failed", "error": "Unsafe path in archive"})
                continue

            inner_name = member_path.name
            extension = Path(inner_name).suffix.lower()
            if extension not in SUPPORTED_TYPES:
                results.append({"file": inner_name, "status": "skipped", "error": f"Unsupported file type: {extension}"})
                continue

            inner_bytes = zf.read(member.filename)
            upload = UploadFile(filename=inner_name, file=io.BytesIO(inner_bytes))
            try:
                outcome = await _process_upload_file(db=db, user=user, upload=upload, masking_mode=masking_mode, batch_id=batch_id)
                outcome["archive"] = Path(archive_name).name
                results.append(outcome)
            except Exception as exc:
                db.rollback()
                results.append({"archive": Path(archive_name).name, "file": inner_name, "status": "failed", "error": str(exc)})

    return results


@router.post("/single")
async def upload_single(
    request: Request,
    file: UploadFile = File(...),
    bureau_field: str = Form(default=""),
    masking_mode: str = Form("redact"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_storage_dirs(settings.raw_storage_path, settings.sanitized_storage_path)
    _bot_guard(db, user, bureau_field, request)
    _enforce_upload_rate_limit(db, user)

    try:
        return await _process_upload_file(db=db, user=user, upload=file, masking_mode=masking_mode, batch_id=None)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Processing failed: {exc}") from exc


@router.post("/bulk")
async def upload_bulk(
    request: Request,
    files: list[UploadFile] | None = File(default=None),
    files_array: list[UploadFile] | None = File(default=None, alias="files[]"),
    bureau_field: str = Form(default=""),
    masking_mode: str = Form("redact"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_storage_dirs(settings.raw_storage_path, settings.sanitized_storage_path)
    _bot_guard(db, user, bureau_field, request)
    _enforce_upload_rate_limit(db, user)

    uploads = (files or []) + (files_array or [])
    if not uploads:
        raise HTTPException(status_code=400, detail="No files provided")

    results = []
    for upload in uploads:
        try:
            if Path(upload.filename).suffix.lower() == ".zip":
                archive_bytes = await upload.read()
                try:
                    results.extend(
                        await _process_zip_archive_bytes(
                            db=db,
                            user=user,
                            archive_name=upload.filename,
                            archive_bytes=archive_bytes,
                            masking_mode=masking_mode,
                            batch_id=None,
                        )
                    )
                except zipfile.BadZipFile as exc:
                    results.append({"file": upload.filename, "status": "failed", "error": f"Invalid zip archive: {exc}"})
            else:
                results.append(await _process_upload_file(db=db, user=user, upload=upload, masking_mode=masking_mode, batch_id=None))
        except Exception as exc:
            db.rollback()
            results.append({"file": upload.filename, "status": "failed", "error": str(exc)})

    return {"count": len(results), "results": results}


@router.post("/batch")
async def upload_batch(
    request: Request,
    files: list[UploadFile] | None = File(default=None),
    files_array: list[UploadFile] | None = File(default=None, alias="files[]"),
    bureau_field: str = Form(default=""),
    masking_mode: str = Form("redact"),
    name: str | None = Form(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_storage_dirs(settings.raw_storage_path, settings.sanitized_storage_path)
    _bot_guard(db, user, bureau_field, request)
    _enforce_upload_rate_limit(db, user)

    uploads = (files or []) + (files_array or [])
    if not uploads:
        raise HTTPException(status_code=400, detail="No files provided")

    batch = CaseBatch(name=name or f"Batch - {now_ist().isoformat()}", user_id=user.id, total_files=len(uploads), completed_files=0)
    db.add(batch)
    db.commit()
    db.refresh(batch)

    results = []
    completed = 0
    for upload in uploads:
        try:
            if Path(upload.filename).suffix.lower() == ".zip":
                archive_bytes = await upload.read()
                zip_results = await _process_zip_archive_bytes(
                    db=db,
                    user=user,
                    archive_name=upload.filename,
                    archive_bytes=archive_bytes,
                    masking_mode=masking_mode,
                    batch_id=batch.id,
                )
                results.extend(zip_results)
                completed += sum(
                    1
                    for r in zip_results
                    if r.get("status") in {FileStatus.sanitized.value, FileStatus.flagged.value} or r.get("duplicate")
                )
            else:
                outcome = await _process_upload_file(
                    db=db, user=user, upload=upload, masking_mode=masking_mode, batch_id=batch.id
                )
                results.append(outcome)
                if outcome.get("status") in {FileStatus.sanitized.value, FileStatus.flagged.value} or outcome.get(
                    "duplicate"
                ):
                    completed += 1
        except Exception as exc:
            db.rollback()
            results.append({"file": upload.filename, "status": "failed", "error": str(exc)})

    batch.completed_files = completed
    db.commit()

    return {"batch_id": batch.id, "count": len(results), "results": results}


@router.get("/batch/{batch_id}/status")
def batch_status(batch_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    batch = db.query(CaseBatch).filter(CaseBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    if user.role != UserRole.admin and batch.user_id != user.id:
        raise HTTPException(status_code=404, detail="Batch not found")

    files = db.query(CaseFile).filter(CaseFile.batch_id == batch.id).all()
    return {
        "batch_id": batch.id,
        "name": batch.name,
        "total_files": batch.total_files,
        "completed_files": batch.completed_files,
        "files": [{"file_id": f.id, "status": f.status.value, "file_type": f.file_type} for f in files],
    }


@router.post("/folder")
async def upload_folder_archive(
    request: Request,
    archive: UploadFile = File(...),
    bureau_field: str = Form(default=""),
    masking_mode: str = Form("redact"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if Path(archive.filename).suffix.lower() != ".zip":
        raise HTTPException(status_code=400, detail="Folder upload expects a .zip archive")

    ensure_storage_dirs(settings.raw_storage_path, settings.sanitized_storage_path)
    _bot_guard(db, user, bureau_field, request)
    _enforce_upload_rate_limit(db, user)

    archive_bytes = await archive.read()
    try:
        results = await _process_zip_archive_bytes(
            db=db,
            user=user,
            archive_name=archive.filename,
            archive_bytes=archive_bytes,
            masking_mode=masking_mode,
            batch_id=None,
        )
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="Invalid zip archive") from exc

    return {"count": len(results), "results": results}






