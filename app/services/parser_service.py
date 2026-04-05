from typing import Optional

from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.schemas.atomic import AtomicIngestionPayload
from app.schemas.falco import FalcoIngestionPayload
from app.schemas.trivy import TrivyIngestionPayload


class ParserService:
    """Normalize tool-specific outputs into canonical Finding format."""

    @staticmethod
    def parse_trivy(db: Session, run_id: int, payload: TrivyIngestionPayload) -> list[Finding]:
        """Convert Trivy JSON vulnerabilities to Finding records."""
        findings = []
        
        for result in payload.results:
            for vuln in result.Vulnerabilities:
                finding = Finding(
                    run_id=run_id,
                    source_tool="trivy",
                    severity=vuln.Severity.lower() if vuln.Severity else "unknown",
                    title=f"{vuln.PkgName}: {vuln.Title}",
                    description=vuln.Description,
                    rule_or_cve_id=vuln.VulnerabilityID,
                    asset_type="package",
                    evidence_json={
                        "cve_id": vuln.VulnerabilityID,
                        "package": vuln.PkgName,
                        "current_version": vuln.PkgVersion,
                        "fixed_version": vuln.FixedVersion,
                        "target": result.Target,
                    },
                )
                db.add(finding)
                findings.append(finding)
        
        db.commit()
        return findings

    @staticmethod
    def parse_falco(db: Session, run_id: int, payload: FalcoIngestionPayload) -> list[Finding]:
        """Convert Falco alerts to Finding records."""
        findings = []
        
        # Priority map: Falco priorities to severity levels
        priority_map = {
            "Emergency": "critical",
            "Alert": "critical",
            "Critical": "critical",
            "Error": "high",
            "Warning": "medium",
            "Notice": "low",
            "Informational": "low",
        }
        
        for alert in payload.alerts:
            severity = priority_map.get(alert.priority, "medium")
            
            # Group by container for correlation
            container_id = alert.container.id if alert.container else "unknown"
            container_name = alert.container.name if alert.container else "unknown"
            
            finding = Finding(
                run_id=run_id,
                source_tool="falco",
                severity=severity,
                title=f"Runtime: {alert.rule}",
                description=alert.output,
                rule_or_cve_id=alert.rule,
                asset_type="container-runtime",
                evidence_json={
                    "rule": alert.rule,
                    "priority": alert.priority,
                    "time": alert.time,
                    "container_id": container_id,
                    "container_name": container_name,
                    "process": alert.process.name if alert.process else None,
                    "file": alert.file.name if alert.file else None,
                },
            )
            db.add(finding)
            findings.append(finding)
        
        db.commit()
        return findings

    @staticmethod
    def parse_atomic(db: Session, run_id: int, payload: AtomicIngestionPayload) -> list[Finding]:
        """Convert Atomic Red Team results to Finding records."""
        findings = []
        
        # Atomic tests map to severity and classification
        status_to_severity = {
            "success": "high",
            "failure": "low",
            "error": "medium",
        }
        
        for test in payload.tests:
            severity = status_to_severity.get(test.status, "medium")
            
            finding = Finding(
                run_id=run_id,
                source_tool="atomic",
                severity=severity,
                title=f"Validation: {test.test_name} ({test.status})",
                description=test.message or f"Atomic test {test.technique_id} executed",
                rule_or_cve_id=test.technique_id,
                asset_type="container-behavior",
                evidence_json={
                    "technique_id": test.technique_id,
                    "technique_name": test.technique_name,
                    "test_name": test.test_name,
                    "status": test.status,
                    "timestamp": test.timestamp,
                    "message": test.message,
                },
            )
            db.add(finding)
            findings.append(finding)
        
        db.commit()
        return findings
