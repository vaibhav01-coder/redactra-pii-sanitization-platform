from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import CaseFile, EventType, User, UserRole
from app.schemas import UserCreate, UserOut
from app.security import get_password_hash
from app.services.audit_service import create_audit_log

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/")
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    create_audit_log(db, event_type=EventType.admin_action, user_id=admin.id, metadata={"action": "list_users"})
    db.commit()
    result = []
    for u in users:
        file_count = db.query(func.count(CaseFile.id)).filter(CaseFile.owner_id == u.id).scalar() or 0
        result.append(
            {
                "id": u.id,
                "email": u.email,
                "role": u.role.value,
                "is_active": u.is_active,
                "created_at": u.created_at.isoformat(),
                "file_count": file_count,
            }
        )
    return result


@router.post("/", response_model=UserOut)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    new_user = User(
        email=payload.email,
        password_hash=get_password_hash(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(new_user)
    create_audit_log(
        db,
        event_type=EventType.admin_action,
        user_id=admin.id,
        metadata={"action": "create_user", "target_email": payload.email, "role": payload.role.value},
    )
    db.commit()
    db.refresh(new_user)
    return new_user


@router.patch("/{user_id}")
def update_user(
    user_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if "is_active" in payload:
        user.is_active = bool(payload["is_active"])
        if user.is_active:
            create_audit_log(db, event_type=EventType.admin_action, user_id=admin.id, metadata={"action": "reactivate_user", "target_user_id": user_id})
        else:
            create_audit_log(db, event_type=EventType.user_suspended, user_id=admin.id, metadata={"target_user_id": user_id, "source": "admin_action"})
    if "role" in payload and payload["role"] == "admin":
        if user.role == UserRole.admin:
            raise HTTPException(status_code=400, detail="User is already admin")
        user.role = UserRole.admin
        create_audit_log(db, event_type=EventType.user_promoted, user_id=admin.id, metadata={"target_user_id": user_id})
    db.commit()
    return {"message": "User updated"}


@router.delete("/{user_id}")
def deactivate_user(user_id: str, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == UserRole.admin:
        raise HTTPException(status_code=400, detail="Cannot deactivate admin")

    user.is_active = False
    create_audit_log(
        db,
        event_type=EventType.user_suspended,
        user_id=admin.id,
        metadata={"target_user_id": user_id, "source": "delete_route"},
    )
    db.commit()
    return {"message": "User access revoked"}
