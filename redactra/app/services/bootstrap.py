from sqlalchemy.orm import Session

from app.models import User, UserRole
from app.security import get_password_hash


def ensure_admin_user(db: Session, email: str, password: str) -> None:
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        return

    db.add(
        User(
            email=email,
            password_hash=get_password_hash(password),
            role=UserRole.admin,
            is_active=True,
        )
    )
    db.commit()
