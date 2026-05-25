from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RunSummary(Base):
    """Run-level executive summary synthesised from all SecurityMatrixEntry rows.

    One row per run (``run_id`` unique). ``top_priorities`` is a JSON-encoded
    list of strings. ``generated_by`` is "llm" when Gemini produced it and
    "static" when it fell back to the templated summary.
    """

    __tablename__ = "run_summaries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("assessment_runs.id"), unique=True, index=True
    )
    headline: Mapped[str] = mapped_column(String(300), default="")
    overall_posture: Mapped[str] = mapped_column(String(1000), default="")
    # JSON-encoded list[str] of prioritised "fix this first" items.
    top_priorities: Mapped[str] = mapped_column(Text, default="[]")
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    source: Mapped[str] = mapped_column(String(100), default="rule-based")
    generated_by: Mapped[str] = mapped_column(String(20), default="static")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
