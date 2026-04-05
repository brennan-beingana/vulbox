from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class CorrelatedFinding(Base):
    __tablename__ = "correlated_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    main_finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    supporting_finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[str] = mapped_column(String(20), default="unknown")
    correlation_reason: Mapped[str] = mapped_column(String(500), default="")
    is_confirmed: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
