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

    # LLM remediation (Google Gemini). Disabled by default so the demo path
    # keeps working without an API key; enable with VULBOX_LLM_REMEDIATION=true.
    llm_remediation_enabled: bool = (
        os.getenv("VULBOX_LLM_REMEDIATION", "false").lower() == "true"
    )
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    # One key, two models: primary serves every call; backup is the failover
    # when the primary errors, rate-limits (429 RESOURCE_EXHAUSTED), or times out.
    llm_model_primary: str = os.getenv("VULBOX_LLM_MODEL_PRIMARY", "gemini-2.5-flash")
    llm_model_backup: str = os.getenv("VULBOX_LLM_MODEL_BACKUP", "gemini-2.5-flash-lite")
    llm_min_risk_score: int = int(os.getenv("VULBOX_LLM_MIN_RISK_SCORE", "20"))
    llm_timeout_secs: int = int(os.getenv("VULBOX_LLM_TIMEOUT_SECS", "30"))
    llm_max_tokens: int = int(os.getenv("VULBOX_LLM_MAX_TOKENS", "1024"))
    # Run-level executive summary: one extra Gemini call synthesising all
    # findings into a prioritised narrative. Falls back to a templated summary.
    llm_exec_summary_enabled: bool = (
        os.getenv("VULBOX_LLM_EXEC_SUMMARY", "true").lower() == "true"
    )


settings = Settings()
