import base64
from cryptography.fernet import Fernet

from app.core.config import settings


class CryptoService:
    def __init__(self) -> None:
        if settings.fernet_key:
            key = settings.fernet_key.encode()
        else:
            # deterministic fallback for local MVP bootstrapping
            key = base64.urlsafe_b64encode((settings.jwt_secret_key * 2)[:32].encode())
        self.fernet = Fernet(key)

    def encrypt_text(self, value: str) -> str:
        return self.fernet.encrypt(value.encode()).decode()

    def decrypt_text(self, value: str) -> str:
        return self.fernet.decrypt(value.encode()).decode()

    def encrypt_bytes(self, value: bytes) -> bytes:
        return self.fernet.encrypt(value)

    def decrypt_bytes(self, value: bytes) -> bytes:
        return self.fernet.decrypt(value)


crypto_service = CryptoService()
