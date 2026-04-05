from datetime import datetime

from pydantic import BaseModel, Field


class RunCreate(BaseModel):
    project_name: str = Field(min_length=1, max_length=200)
    repo_url: str = ""
    branch: str = "main"
    commit_sha: str = ""
    image_name: str = ""
    image_tag: str = "latest"
    source_type: str = "repo"
    triggered_by: str = "manual"
    llm_remediation_enabled: bool = False


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
    source_type: str
    status: str
    triggered_by: str
    llm_remediation_enabled: bool
    started_at: datetime
    finished_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True
