from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CASE FILED API"
    environment: str = "dev"
    debug: bool = True

    database_url: str = "sqlite:///./case_filed.db"

    jwt_secret_key: str = "change-me-super-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    fernet_key: str = ""
    tesseract_cmd: str = ""
    virustotal_api_key: str = ""

    storage_root: str = "storage"
    raw_bucket: str = "raw-files"
    sanitized_bucket: str = "sanitized-files"

    supabase_url: str = ""
    supabase_service_role_key: str = ""
    supabase_raw_bucket: str = "raw-files"
    supabase_sanitized_bucket: str = "sanitized-files"

    initial_admin_email: str = "lead.detective@casefiled.com"
    initial_admin_password: str = "ChangeMe123!"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @field_validator("database_url", mode="before")
    @classmethod
    def default_database_url(cls, value: str | None) -> str:
        if value is None:
            return "sqlite:///./case_filed.db"
        if isinstance(value, str) and not value.strip():
            return "sqlite:///./case_filed.db"
        return value

    @property
    def raw_storage_path(self) -> Path:
        return Path(self.storage_root) / self.raw_bucket

    @property
    def sanitized_storage_path(self) -> Path:
        return Path(self.storage_root) / self.sanitized_bucket

    @property
    def use_supabase_storage(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_role_key)


settings = Settings()
