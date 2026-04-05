from datetime import datetime

from pydantic import BaseModel, Field


class FindingCreate(BaseModel):
    source_tool: str = Field(min_length=1, max_length=50)
    severity: str = Field(min_length=1, max_length=20)
    title: str = Field(min_length=1, max_length=300)
    description: str = ""
    rule_or_cve_id: str = ""
    asset_type: str = "container-image"
    evidence_json: dict = Field(default_factory=dict)


class FindingResponse(BaseModel):
    id: int
    run_id: int
    source_tool: str
    severity: str
    title: str
    description: str
    rule_or_cve_id: str
    asset_type: str
    evidence_json: dict
    created_at: datetime

    class Config:
        from_attributes = True
