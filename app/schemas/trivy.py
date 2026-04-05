from typing import List, Optional

from pydantic import BaseModel, Field


class TrivyVulnerability(BaseModel):
    VulnerabilityID: str
    Severity: str
    Title: str
    Description: str
    PkgName: str
    PkgVersion: str
    FixedVersion: Optional[str] = None


class TrivyResult(BaseModel):
    Target: str
    Class: str
    Type: str
    Vulnerabilities: List[TrivyVulnerability] = Field(default_factory=list)


class TrivyIngestionPayload(BaseModel):
    results: List[TrivyResult]
    image_tag: str


class TrivyResponse(BaseModel):
    message: str
    findings_count: int
