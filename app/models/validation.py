from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Validation(Base):
    __tablename__ = "validations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    test_name: Mapped[str] = mapped_column(String(200), nullable=False)
    mitre_technique: Mapped[str] = mapped_column(String(50), default="")
    result: Mapped[str] = mapped_column(String(50), default="unknown")
    consent_given: Mapped[bool] = mapped_column(default=False)
    sandboxed: Mapped[bool] = mapped_column(default=True)
    notes: Mapped[str] = mapped_column(String(1000), default="")
    executed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
