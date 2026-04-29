import os
from pathlib import Path

from pydantic import BaseModel

# Project root: parents[2] = <repo>/ since this file is <repo>/app/core/config.py
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]


class Settings(BaseModel):
    app_name: str = "VulBox Security Assessment"
    app_version: str = "0.2.0"
    database_url: str = "sqlite:///./data/findings.db"
    secret_key: str = os.getenv("VULBOX_SECRET_KEY", "dev-secret-key-change-in-production")
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24  # 24 hours
    dev_mode: bool = os.getenv("VULBOX_DEV_MODE", "true").lower() == "true"
    project_root: Path = PROJECT_ROOT


settings = Settings()
