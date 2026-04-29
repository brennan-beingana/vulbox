from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Remediation(Base):
    __tablename__ = "remediations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    matrix_entry_id: Mapped[int] = mapped_column(
        ForeignKey("security_matrix_entries.entry_id"), nullable=False
    )
    summary: Mapped[str] = mapped_column(String(300), nullable=False)
    priority_action: Mapped[str] = mapped_column(String(500), nullable=False)
    why_it_matters: Mapped[str] = mapped_column(String(500), default="")
    example_fix: Mapped[str] = mapped_column(String(1000), default="")
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    source: Mapped[str] = mapped_column(String(100), default="rule-based")
    # "static" (rule-based) or "llm" — drives UI badge in the Report screen.
    generated_by: Mapped[str] = mapped_column(String(20), default="static")
    references: Mapped[str] = mapped_column(String(2000), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
