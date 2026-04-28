from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Status states (SDD §4.10)
STATUSES = ("SUBMITTED", "BUILDING", "SCANNING", "TESTING", "REBUILDING", "REPORTING", "COMPLETE", "FAILED")


class AssessmentRun(Base):
    __tablename__ = "assessment_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_name: Mapped[str] = mapped_column(String(200), nullable=False)
    repo_url: Mapped[str] = mapped_column(String(500), default="")
    branch: Mapped[str] = mapped_column(String(120), default="main")
    commit_sha: Mapped[str] = mapped_column(String(80), default="")
    image_name: Mapped[str] = mapped_column(String(200), default="")
    image_tag: Mapped[str] = mapped_column(String(120), default="latest")
    status: Mapped[str] = mapped_column(String(50), default="SUBMITTED")
    submitted_by: Mapped[str] = mapped_column(String(200), default="")
    consent_granted: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
