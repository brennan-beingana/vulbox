from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ARTTestResult(Base):
    __tablename__ = "art_test_results"

    test_result_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    mitre_test_id: Mapped[str] = mapped_column(String(50), nullable=False)
    exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    crash_occurred: Mapped[bool] = mapped_column(Boolean, default=False)
    executed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
