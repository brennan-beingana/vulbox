from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class TrivyFindingSchema(BaseModel):
    finding_id: int
    cve_id: str
    severity: str
    package_name: str
    fix_available: bool

    class Config:
        from_attributes = True


class SecurityMatrixEntrySchema(BaseModel):
    entry_id: int
    finding_id: Optional[int]
    test_result_id: Optional[int]
    is_present: bool
    is_exploitable: bool
    is_detectable: bool
    mitre_tactic_id: str
    risk_score: int

    class Config:
        from_attributes = True


class RemediationResponseSchema(BaseModel):
    id: int
    matrix_entry_id: int
    summary: str
    priority_action: str
    why_it_matters: str
    example_fix: str
    confidence: str
    source: str
    generated_by: str = "static"
    references: str = ""

    class Config:
        from_attributes = True


class ARTTestResultSchema(BaseModel):
    test_result_id: int
    mitre_test_id: str
    exploited: bool
    crash_occurred: bool
    executed_at: datetime

    class Config:
        from_attributes = True


class ReportResponse(BaseModel):
    run_id: int
    project_name: str
    image_tag: str
    status: str
    trivy_findings_count: int
    art_tests_count: int
    remediations_count: int
    security_matrix: List[SecurityMatrixEntrySchema]
    remediations: List[RemediationResponseSchema]
    created_at: datetime
