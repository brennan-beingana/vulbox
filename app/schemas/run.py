from datetime import datetime

from pydantic import BaseModel, Field, field_validator

_SEVERITY_LEVELS = ("critical", "high", "medium", "low")


class RunCreate(BaseModel):
    project_name: str = Field(min_length=1, max_length=200)
    repo_url: str = ""
    branch: str = "main"
    commit_sha: str = ""
    image_name: str = ""
    image_tag: str = "latest"
    consent_granted: bool = False
    # Minimum CVE severity to attribute an exploitability (matrix) row to.
    # The technique still runs; only findings at/above this level get their own
    # row, which bounds report size. "high" tests Critical+High by default.
    min_severity: str = "high"

    @field_validator("min_severity", mode="before")
    @classmethod
    def _normalize_severity(cls, v: str) -> str:
        v = (v or "high").strip().lower()
        return v if v in _SEVERITY_LEVELS else "high"


class RunUpdate(BaseModel):
    status: str


class RunResponse(BaseModel):
    id: int
    project_name: str
    repo_url: str
    branch: str
    commit_sha: str
    image_name: str
    image_tag: str
    status: str
    submitted_by: str
    consent_granted: bool
    min_severity: str = "high"
    started_at: datetime
    completed_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True
