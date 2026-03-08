import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.time import now_ist
from app.database import get_db
from app.models import EventType, RefreshToken, User, UserRole
from app.schemas import LoginRequest, RefreshRequest, TokenResponse, UserCreate, UserOut
from app.security import create_access_token, create_refresh_token, get_password_hash, verify_password, decode_token
from app.services.audit_service import create_audit_log

router = APIRouter(prefix="/auth", tags=["auth"])


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _issue_tokens(user: User, db: Session, rotated_from: str | None = None) -> TokenResponse:
    access_token = create_access_token(subject=user.id, role=user.role.value)
    refresh_token, refresh_exp = create_refresh_token(subject=user.id, role=user.role.value)

    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=_hash_token(refresh_token),
            expires_at=refresh_exp,
            revoked=False,
            rotated_from=rotated_from,
        )
    )
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


def _issue_token_for_credentials(email: str, password: str, db: Session) -> TokenResponse:
    user = db.query(User).filter(User.email == email, User.is_active.is_(True)).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    pair = _issue_tokens(user, db)
    create_audit_log(db, event_type=EventType.login, user_id=user.id, metadata={"email": user.email})
    db.commit()
    return pair


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    return _issue_token_for_credentials(payload.email, payload.password, db)


@router.post("/token", response_model=TokenResponse)
def token_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Swagger OAuth2 password popup sends username/password as form fields.
    return _issue_token_for_credentials(form_data.username, form_data.password, db)


@router.post("/refresh", response_model=TokenResponse)
def refresh_access_token(payload: RefreshRequest, db: Session = Depends(get_db)):
    try:
        parsed = decode_token(payload.refresh_token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc

    if parsed.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user_id = parsed.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    token_hash = _hash_token(payload.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    if not stored or stored.revoked:
        raise HTTPException(status_code=401, detail="Refresh token expired or revoked")
    # Refresh token expiry is stored in UTC; SQLite may return naive datetime
    expires_at = stored.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired or revoked")

    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    stored.revoked = True
    pair = _issue_tokens(user, db, rotated_from=stored.id)
    db.commit()
    return pair


@router.post("/register", response_model=UserOut)
def register_user(payload: UserCreate, request: Request, db: Session = Depends(get_db)):
    if payload.bureau_field:
        create_audit_log(
            db,
            event_type=EventType.bot_detected,
            user_id=None,
            metadata={
                "email": payload.email,
                "ip": request.client.host if request.client else "",
                "user_agent": request.headers.get("user-agent", ""),
                "source": "register",
            },
        )
        db.commit()
        raise HTTPException(status_code=422, detail="Invalid submission")

    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    # Public self-registration is user-only; admin accounts remain bootstrap/admin-controlled.
    new_user = User(
        email=payload.email,
        password_hash=get_password_hash(payload.password),
        role=UserRole.user,
        is_active=True,
    )
    db.add(new_user)
    create_audit_log(
        db,
        event_type=EventType.admin_action,
        user_id=None,
        metadata={"action": "self_register", "target_email": payload.email, "role": UserRole.user.value},
    )
    db.commit()
    db.refresh(new_user)
    return new_user
