from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root: parents[2] = <repo>/ since this file is <repo>/app/core/config.py
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Runtime configuration.

    Resolution order (highest priority first): real process environment →
    ``<repo>/.env`` file → field default. The ``.env`` file is what makes
    production mode persist across restarts/reboots without re-exporting vars
    (``.env`` is gitignored; see ``.env.example`` for the documented keys).

    Each env-backed field declares an explicit ``validation_alias`` so the
    public ``VULBOX_*`` / ``GEMINI_API_KEY`` names stay exactly as documented
    regardless of the internal field name.
    """

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "VulBox Security Assessment"
    app_version: str = "0.2.0"
    database_url: str = "sqlite:///./data/findings.db"
    secret_key: str = Field(
        default="dev-secret-key-change-in-production",
        validation_alias="VULBOX_SECRET_KEY",
    )
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24  # 24 hours

    # Bootstrap admin. Seeded once at startup if no user with this email exists,
    # so there is always an account that can see every run (run-scoping below).
    # Self-registration always creates a `provider`, so an admin can only be
    # minted here. Leave admin_email blank to disable seeding.
    admin_email: str = Field(default="", validation_alias="VULBOX_ADMIN_EMAIL")
    admin_password: str = Field(default="", validation_alias="VULBOX_ADMIN_PASSWORD")
    # Dev mode replays fixtures and never launches Docker/Trivy/Falco. Default
    # True keeps the demo/test path zero-config; set VULBOX_DEV_MODE=false in
    # .env for a real assessment host.
    dev_mode: bool = Field(default=True, validation_alias="VULBOX_DEV_MODE")
    project_root: Path = PROJECT_ROOT

    # Persistent cache for cloned target repos. Remote repo_urls are cloned once
    # into <local_repos_dir>/<slug> and reused on later runs, so a transient
    # `git clone` failure on a re-run degrades to the cached checkout instead of
    # failing the build. Override with VULBOX_LOCAL_REPOS_DIR.
    local_repos_dir: Path = Field(
        default=Path("/home/code/local-repos"),
        validation_alias="VULBOX_LOCAL_REPOS_DIR",
    )

    # Default sandbox read-only posture when a target has no .vulbox.yml. False
    # lets the app write to its own disk inside the throwaway container, which
    # most real server stacks (tomcat/apache/rails/elasticsearch) need just to
    # boot — under read-only they crash on startup and the run fails before any
    # scanning/testing. A repo's .vulbox.yml `sandbox.read_only` still overrides
    # this per-target. Set VULBOX_SANDBOX_READ_ONLY=true to re-lock the default.
    sandbox_default_read_only: bool = Field(
        default=False, validation_alias="VULBOX_SANDBOX_READ_ONLY"
    )

    # LLM remediation (Google Gemini). Disabled by default so the demo path
    # keeps working without an API key; enable with VULBOX_LLM_REMEDIATION=true.
    llm_remediation_enabled: bool = Field(
        default=False, validation_alias="VULBOX_LLM_REMEDIATION"
    )
    gemini_api_key: str = Field(default="", validation_alias="GEMINI_API_KEY")
    # One key, two models: primary serves every call; backup is the failover
    # when the primary errors, rate-limits (429 RESOURCE_EXHAUSTED), or times out.
    llm_model_primary: str = Field(
        default="gemini-2.5-flash", validation_alias="VULBOX_LLM_MODEL_PRIMARY"
    )
    llm_model_backup: str = Field(
        default="gemini-2.5-flash-lite", validation_alias="VULBOX_LLM_MODEL_BACKUP"
    )
    # Entries at/above this risk_score get a Gemini call; everything else uses
    # the static rule. Default 25 = the report's high (orange) band, so both
    # high- and critical-band findings get LLM guidance while low/medium stay
    # static. Raise to 40 (critical only) to spend even less quota.
    llm_min_risk_score: int = Field(
        default=25, validation_alias="VULBOX_LLM_MIN_RISK_SCORE"
    )
    # Hard ceiling on Gemini calls per run, on top of the risk threshold. Since
    # entries are processed highest-risk-first, the top-N qualifying entries get
    # the LLM; the rest fall back to static. Bounds free-tier quota/rate-limit
    # exposure even when a run has many high/critical findings. ≤0 = no cap.
    llm_max_calls: int = Field(default=15, validation_alias="VULBOX_LLM_MAX_CALLS")
    llm_timeout_secs: int = Field(default=30, validation_alias="VULBOX_LLM_TIMEOUT_SECS")
    llm_max_tokens: int = Field(default=1024, validation_alias="VULBOX_LLM_MAX_TOKENS")
    # Run-level executive summary: one extra Gemini call synthesising all
    # findings into a prioritised narrative. Falls back to a templated summary.
    llm_exec_summary_enabled: bool = Field(
        default=True, validation_alias="VULBOX_LLM_EXEC_SUMMARY"
    )

    # EPSS gate for fan-out matrix entries. 0.0 = off (every motivating CVE
    # that maps to a tested technique gets a matrix row). When raised, only
    # CVEs whose EPSS score meets the threshold are attributed per-CVE
    # (KEV/ransomware-flagged CVEs are always included), keeping large scans
    # bounded while the technique itself still runs once.
    epss_min: float = Field(default=0.0, validation_alias="VULBOX_EPSS_MIN")

    # Trivy scan timeout (seconds), passed to `trivy --timeout` AND used as the
    # subprocess cap (+60s slack). Default 600 — the built-in 300 was too tight
    # for very large images (thousands of npm/OS packages). Raise for monsters.
    trivy_timeout_secs: int = Field(
        default=600, validation_alias="VULBOX_TRIVY_TIMEOUT_SECS"
    )


settings = Settings()
