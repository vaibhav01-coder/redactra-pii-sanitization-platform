from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import EventType, User, UserRole
from app.security import decode_token
from app.services.audit_service import create_audit_log

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        token_type = payload.get("type", "access")
        if not user_id or token_type != "access":
            raise credentials_exception
    except ValueError as exc:
        raise credentials_exception from exc

    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if not user:
        raise credentials_exception
    return user


def require_admin(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
    if user.role != UserRole.admin:
        create_audit_log(
            db,
            event_type=EventType.access_denied,
            user_id=user.id,
            metadata={"reason": "admin_required"},
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
