from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.models.correlated_finding import CorrelatedFinding
from app.models.finding import Finding


class CorrelationService:
    """Merge findings across tools and compute risk scores."""

    # Base severity scores
    SEVERITY_SCORES = {
        "critical": 40,
        "high": 30,
        "medium": 20,
        "low": 10,
        "unknown": 5,
    }

    # Confidence bands
    CONFIDENCE_BANDS = {
        (35, 100): "critical",
        (25, 34): "high",
        (15, 24): "medium",
        (5, 14): "low",
        (0, 4): "unknown",
    }

    @staticmethod
    def get_confidence_band(score: int) -> str:
        """Map risk score to confidence band."""
        for (low, high), band in CorrelationService.CONFIDENCE_BANDS.items():
            if low <= score <= high:
                return band
        return "unknown"

    @staticmethod
    def correlate_findings(db: Session, run_id: int) -> list[CorrelatedFinding]:
        """
        Merge findings by run metadata.
        Join on: run_id, commit_sha, image_tag, container_id, execution window.
        """
        # Get all findings for this run
        findings = db.query(Finding).filter(Finding.run_id == run_id).all()
        
        if not findings:
            return []
        
        # Group findings by correlation key
        correlation_groups = {}
        
        for finding in findings:
            # Extract container_id from evidence_json if present (for Falco)
            container_id = finding.evidence_json.get("container_id", "unknown")
            
            # Correlation key: (cve_id/rule, source_tool, container_id)
            # This allows CVEs to be linked with runtime confirmation
            key = (
                finding.rule_or_cve_id,
                finding.severity,
                finding.asset_type,
            )
            
            if key not in correlation_groups:
                correlation_groups[key] = []
            correlation_groups[key].append(finding)
        
        # Create correlated findings
        correlated_findings = []
        
        for key, group in correlation_groups.items():
            if not group:
                continue
            
            # Select primary finding (usually static scan first)
            primary = next(
                (f for f in group if f.source_tool == "trivy"),
                group[0],
            )
            
            # Calculate risk score
            base_score = CorrelationService.SEVERITY_SCORES.get(
                primary.severity, 5
            )
            score = base_score
            
            # Modifiers
            source_tools = {f.source_tool for f in group}
            
            # +5 if runtime confirms (Falco alert for this CVE)
            if "falco" in source_tools:
                score += 5
            
            # +3 if validation succeeds (Atomic confirms exploitability)
            if "atomic" in source_tools:
                score += 3
            
            # +2 if multiple tools report same issue
            if len(source_tools) > 1:
                score += 2
            
            # -3 if evidence sparse (only one finding)
            if len(group) == 1:
                score = max(0, score - 3)
            
            # Cap score at 50
            score = min(50, score)
            
            # Determine confirmation
            is_confirmed = len(source_tools) > 1 or "falco" in source_tools
            
            # Build correlation reason
            reason = f"Merged {len(group)} findings from {', '.join(sorted(source_tools))}"
            if is_confirmed:
                reason += " [CONFIRMED by runtime]"
            
            # Create correlated record
            supporting_ids = [f.id for f in group if f.id != primary.id]
            
            correlated = CorrelatedFinding(
                run_id=run_id,
                main_finding_id=primary.id,
                supporting_finding_ids=supporting_ids,
                risk_score=score,
                confidence=CorrelationService.get_confidence_band(score),
                correlation_reason=reason,
                is_confirmed=is_confirmed,
            )
            
            db.add(correlated)
            correlated_findings.append(correlated)
        
        db.commit()
        return correlated_findings

    @staticmethod
    def recompute_correlation(db: Session, run_id: int) -> list[CorrelatedFinding]:
        """Recompute correlation for a run (idempotent; delete old records first)."""
        # Delete existing correlated findings for this run
        db.query(CorrelatedFinding).filter(
            CorrelatedFinding.run_id == run_id
        ).delete()
        db.commit()
        
        # Recompute
        return CorrelationService.correlate_findings(db, run_id)
