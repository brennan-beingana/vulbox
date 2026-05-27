from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class TrivyFindingSchema(BaseModel):
    finding_id: int
    cve_id: str
    severity: str
    package_name: str
    fix_available: bool
    cwe_ids: str = ""
    epss_score: Optional[float] = None

    class Config:
        from_attributes = True


class CoverageSchema(BaseModel):
    """Exploitability-testing coverage: how many detected CVEs got a verdict."""

    detected_cves: int
    tested_cves: int


class DetectedTechnologySchema(BaseModel):
    name: str
    version: Optional[str] = None
    source: str
    confidence: float

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
    cve_id: Optional[str] = None
    epss_score: Optional[float] = None
    # How the motivating CVE resolved to this technique: "cve-map" (direct
    # curated/generated mapping, higher confidence) vs "cwe-bridge" (coarser
    # CWE→technique fallback). None for proactive/fallback techniques.
    match_source: Optional[str] = None

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


class ExecutiveSummarySchema(BaseModel):
    headline: str
    overall_posture: str
    top_priorities: List[str]
    confidence: str
    source: str
    generated_by: str = "static"


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
    detected_technologies: List[DetectedTechnologySchema] = []
    security_matrix: List[SecurityMatrixEntrySchema]
    remediations: List[RemediationResponseSchema]
    executive_summary: Optional[ExecutiveSummarySchema] = None
    coverage: Optional[CoverageSchema] = None
    created_at: datetime
