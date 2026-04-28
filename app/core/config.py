import os

from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "VulBox Security Assessment"
    app_version: str = "0.2.0"
    database_url: str = "sqlite:///./data/findings.db"
    secret_key: str = os.getenv("VULBOX_SECRET_KEY", "dev-secret-key-change-in-production")
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24  # 24 hours
    dev_mode: bool = os.getenv("VULBOX_DEV_MODE", "true").lower() == "true"


settings = Settings()
