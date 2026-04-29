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

    # LLM remediation (OpenAI). Disabled by default so the demo path keeps
    # working without an API key; enable with VULBOX_LLM_REMEDIATION=true.
    llm_remediation_enabled: bool = (
        os.getenv("VULBOX_LLM_REMEDIATION", "false").lower() == "true"
    )
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    llm_model: str = os.getenv("VULBOX_LLM_MODEL", "gpt-4o-mini")
    llm_min_risk_score: int = int(os.getenv("VULBOX_LLM_MIN_RISK_SCORE", "20"))
    llm_timeout_secs: int = int(os.getenv("VULBOX_LLM_TIMEOUT_SECS", "30"))
    llm_max_tokens: int = int(os.getenv("VULBOX_LLM_MAX_TOKENS", "1024"))


settings = Settings()
