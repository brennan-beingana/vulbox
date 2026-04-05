from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_name: Mapped[str] = mapped_column(String(200), nullable=False)
    repo_url: Mapped[str] = mapped_column(String(500), default="")
    branch: Mapped[str] = mapped_column(String(120), default="main")
    commit_sha: Mapped[str] = mapped_column(String(80), default="")
    image_name: Mapped[str] = mapped_column(String(200), default="")
    image_tag: Mapped[str] = mapped_column(String(120), default="latest")
    source_type: Mapped[str] = mapped_column(String(50), default="repo")
    status: Mapped[str] = mapped_column(String(50), default="created")
    triggered_by: Mapped[str] = mapped_column(String(120), default="manual")
    llm_remediation_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
