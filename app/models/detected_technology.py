from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class DetectedTechnology(Base):
    """A technology fingerprinted from the target's Dockerfile/manifests.

    Populated once per run by StackDetector during BUILDING. Drives the
    stack-aware ART test selection and is surfaced in the report.
    """

    __tablename__ = "detected_technologies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[str] = mapped_column(String(80), nullable=True)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
