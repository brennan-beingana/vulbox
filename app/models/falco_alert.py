from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class FalcoAlert(Base):
    __tablename__ = "falco_alerts"

    alert_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    # FK to the ART test that triggered detection (makes Detectability measurable per-test)
    test_result_id: Mapped[int | None] = mapped_column(
        ForeignKey("art_test_results.test_result_id"), nullable=True
    )
    rule_triggered: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    syscall_context: Mapped[str] = mapped_column(String(500), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    detected: Mapped[bool] = mapped_column(Boolean, default=True)
