from datetime import datetime

from pydantic import BaseModel, Field


class RunCreate(BaseModel):
    project_name: str = Field(min_length=1, max_length=200)
    repo_url: str = ""
    branch: str = "main"
    commit_sha: str = ""
    image_name: str = ""
    image_tag: str = "latest"
    consent_granted: bool = False


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
    started_at: datetime
    completed_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True
