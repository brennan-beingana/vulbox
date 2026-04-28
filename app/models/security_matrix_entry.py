from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SecurityMatrixEntry(Base):
    """Three-dimensional security output: Presence × Exploitability × Detectability (SDD §4.13)."""

    __tablename__ = "security_matrix_entries"

    entry_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("trivy_findings.finding_id"), nullable=True
    )
    test_result_id: Mapped[int | None] = mapped_column(
        ForeignKey("art_test_results.test_result_id"), nullable=True
    )
    is_present: Mapped[bool] = mapped_column(Boolean, default=True)
    is_exploitable: Mapped[bool] = mapped_column(Boolean, default=False)
    is_detectable: Mapped[bool] = mapped_column(Boolean, default=False)
    mitre_tactic_id: Mapped[str] = mapped_column(String(50), default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
