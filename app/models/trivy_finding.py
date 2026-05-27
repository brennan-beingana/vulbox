from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class TrivyFinding(Base):
    __tablename__ = "trivy_findings"

    finding_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    cve_id: Mapped[str] = mapped_column(String(120), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    package_name: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(String(2000), default="")
    fix_available: Mapped[bool] = mapped_column(Boolean, default=False)
    # CWE IDs from Trivy (comma-joined, e.g. "CWE-79,CWE-787"); the scan-time
    # bridge in art_adapter maps these to ART techniques when the CVE itself
    # isn't in the curated/generated CVE→technique map.
    cwe_ids: Mapped[str] = mapped_column(String(200), default="")
    # EPSS exploitation-probability (0.0–1.0), enriched from the vendored
    # snapshot; None when the CVE isn't scored. Drives queue ranking + gating.
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
