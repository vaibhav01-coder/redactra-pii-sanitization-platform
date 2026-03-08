import enum
import uuid
from datetime import datetime, timedelta

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.time import now_ist
from app.database import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"


class FileStatus(str, enum.Enum):
    pending_scan = "PENDING_SCAN"
    scan_passed = "SCAN_PASSED"
    flagged = "FLAGGED"
    scanning = "SCANNING"
    sanitized = "SANITIZED"
    failed = "FAILED"
    # Backward compatibility for previous values
    pending = "pending"
    completed = "completed"


class ScanStatus(str, enum.Enum):
    pending = "PENDING"
    passed = "PASSED"
    quarantined = "QUARANTINED"


class EventType(str, enum.Enum):
    upload = "upload"
    scan_start = "scan_start"
    scan_complete = "scan_complete"
    pii_found = "pii_found"
    masked = "masked"
    download = "download"
    login = "login"
    logout = "logout"
    admin_action = "admin_action"

    malware_scan_passed = "MALWARE_SCAN_PASSED"
    malware_scan_failed = "MALWARE_SCAN_FAILED"
    file_flagged = "FILE_FLAGGED"
    auto_deleted = "AUTO_DELETED"
    duplicate_detected = "DUPLICATE_DETECTED"
    bot_detected = "BOT_DETECTED"
    exif_stripped = "EXIF_STRIPPED"
    magic_byte_mismatch = "MAGIC_BYTE_MISMATCH"
    user_suspended = "USER_SUSPENDED"
    context_skip = "CONTEXT_SKIP"
    access_denied = "ACCESS_DENIED"
    false_positive_override = "FALSE_POSITIVE_OVERRIDE"
    token_restored = "TOKEN_RESTORED"
    user_promoted = "USER_PROMOTED"
    file_sanitized = "FILE_SANITIZED"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.user, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_ist, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    rotated_from: Mapped[str | None] = mapped_column(String(36), ForeignKey("refresh_tokens.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_ist, nullable=False)


class HoneypotStrike(Base):
    __tablename__ = "honeypot_strikes"

    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), primary_key=True)
    strike_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_triggered_at: Mapped[datetime] = mapped_column(DateTime, default=now_ist, nullable=False)


class CaseBatch(Base):
    __tablename__ = "file_batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    total_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completed_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_ist, nullable=False)


class CaseFile(Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_path: Mapped[str] = mapped_column(String(500), nullable=False)
    sanitized_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[FileStatus] = mapped_column(Enum(FileStatus), default=FileStatus.pending_scan, nullable=False)
    scan_status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pii_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    uploaded_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    batch_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("file_batches.id"), nullable=True, index=True)
    file_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    vt_report: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    exif_stripped: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_ist, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: now_ist() + timedelta(hours=24), nullable=False, index=True)

    entities: Mapped[list["PiiEntity"]] = relationship(back_populates="case_file", cascade="all, delete-orphan")


class PiiEntity(Base):
    __tablename__ = "pii_entities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id: Mapped[str] = mapped_column(String(36), ForeignKey("files.id"), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    original_value: Mapped[str] = mapped_column(Text, nullable=False)
    masked_value: Mapped[str] = mapped_column(Text, nullable=False)
    token_key: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    detection_layer: Mapped[str] = mapped_column(String(30), nullable=False)
    char_start: Mapped[int] = mapped_column(Integer, nullable=False)
    char_end: Mapped[int] = mapped_column(Integer, nullable=False)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    case_file: Mapped[CaseFile] = relationship(back_populates="entities")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type: Mapped[EventType] = mapped_column(Enum(EventType), nullable=False)
    file_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("files.id"), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_ist, nullable=False, index=True)
