"""
One-off script: Remove all files from the database and create a normal user.
Run from project root: py -m scripts.reset_files_and_create_user
"""
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import SessionLocal
from app.models import CaseBatch, CaseFile, PiiEntity, User, UserRole
from app.security import get_password_hash

NORMAL_USER_EMAIL = "user@redactra.com"
NORMAL_USER_PASSWORD = "UserPass123!"


def main():
    db = SessionLocal()
    try:
        # Delete PII entities first (referenced by files)
        deleted_pii = db.query(PiiEntity).delete()
        # Delete all case files
        deleted_files = db.query(CaseFile).delete()
        # Delete all batches
        deleted_batches = db.query(CaseBatch).delete()

        # Create normal user if not exists
        existing = db.query(User).filter(User.email == NORMAL_USER_EMAIL).first()
        if existing:
            print(f"Normal user already exists: {NORMAL_USER_EMAIL}")
        else:
            user = User(
                email=NORMAL_USER_EMAIL,
                password_hash=get_password_hash(NORMAL_USER_PASSWORD),
                role=UserRole.user,
                is_active=True,
            )
            db.add(user)
            db.flush()
            print(f"Created normal user: {NORMAL_USER_EMAIL}")

        db.commit()
        print(f"Removed: {deleted_pii} PII entities, {deleted_files} files, {deleted_batches} batches.")
        print("---")
        print("Normal user login:")
        print(f"  Email:    {NORMAL_USER_EMAIL}")
        print(f"  Password: {NORMAL_USER_PASSWORD}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
