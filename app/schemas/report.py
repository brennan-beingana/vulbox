from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class RemediationResponseSchema(BaseModel):
    id: int
    summary: str
    priority_action: str
    why_it_matters: str
    example_fix: str
    confidence: str
    source: str


class CorrelatedFindingResponseSchema(BaseModel):
    id: int
    main_finding_id: int
    supporting_finding_ids: List[int]
    risk_score: int
    confidence: str
    correlation_reason: str
    is_confirmed: bool
    finding_title: Optional[str] = None
    finding_severity: Optional[str] = None


class ReportResponse(BaseModel):
    run_id: int
    project_name: str
    image_tag: str
    status: str
    findings_count: int
    correlated_findings_count: int
    remediations_count: int
    correlated_findings: List[CorrelatedFindingResponseSchema]
    remediations: List[RemediationResponseSchema]
    created_at: datetime
