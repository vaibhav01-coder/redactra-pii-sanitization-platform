from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr

from app.models import EventType, FileStatus, UserRole


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: UserRole = UserRole.user
    bureau_field: str = ""


class UserOut(BaseModel):
    id: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseFileOut(BaseModel):
    id: str
    file_type: str
    status: FileStatus
    risk_score: int
    pii_count: int
    created_at: datetime
    uploaded_by: str
    owner_id: str | None = None
    expires_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class PiiEntityOut(BaseModel):
    id: str
    entity_type: str
    masked_value: str
    token_key: str | None
    confidence: float
    detection_layer: str
    char_start: int
    char_end: int
    original_value: str | None = None

    model_config = ConfigDict(from_attributes=True)


class CaseResultOut(BaseModel):
    file: CaseFileOut
    entities: list[PiiEntityOut]


class OverrideRequest(BaseModel):
    entity_id: str
    is_false_positive: bool = True


class DetokenizeRequest(BaseModel):
    token_key: str


class DetokenizeResponse(BaseModel):
    token_key: str
    original_value: str


class BulkDownloadRequest(BaseModel):
    file_ids: list[str]


class AuditLogOut(BaseModel):
    id: str
    event_type: EventType
    file_id: str | None
    user_id: str | None
    metadata_json: dict[str, Any]
    prev_hash: str
    entry_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
