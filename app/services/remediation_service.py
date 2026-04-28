from sqlalchemy.orm import Session

from app.models.remediation import Remediation
from app.models.security_matrix_entry import SecurityMatrixEntry
from app.models.trivy_finding import TrivyFinding


class RemediationService:
    """Generate rule-based remediation guidance from SecurityMatrixEntry rows."""

    REMEDIATION_RULES = {
        "exploitable_undetected": {
            "action": "Patch immediately and deploy detection rules",
            "why": "Vulnerability is exploitable and not detected by runtime monitoring",
            "example": "Upgrade package, add Falco rule for this technique, run Trivy in CI",
            "confidence": "critical",
        },
        "exploitable_detected": {
            "action": "Patch the vulnerability — detection is working",
            "why": "Vulnerability is exploitable; runtime monitoring caught the attempt",
            "example": "Upgrade vulnerable package and keep Falco rule active",
            "confidence": "high",
        },
        "present_not_exploitable": {
            "action": "Monitor and schedule remediation in next sprint",
            "why": "Vulnerability present but not currently exploitable in this environment",
            "example": "Track with ticket, upgrade in next maintenance window",
            "confidence": "medium",
        },
        "cve_default": {
            "action": "Upgrade vulnerable package to fixed version",
            "why": "Known vulnerability with documented attack surface",
            "example": "Run: apt-get update && apt-get upgrade -y",
            "confidence": "high",
        },
    }

    @staticmethod
    def generate_remediations(db: Session, run_id: int) -> list[Remediation]:
        entries = (
            db.query(SecurityMatrixEntry)
            .filter(SecurityMatrixEntry.run_id == run_id)
            .all()
        )

        remediations: list[Remediation] = []
        for entry in entries:
            action, why, example, confidence = RemediationService._pick_rule(entry)
            summary = RemediationService._build_summary(db, entry)

            rem = Remediation(
                run_id=run_id,
                matrix_entry_id=entry.entry_id,
                summary=summary,
                priority_action=action,
                why_it_matters=why,
                example_fix=example,
                confidence=confidence,
                source="rule-based",
            )
            db.add(rem)
            remediations.append(rem)

        db.commit()
        return remediations

    @staticmethod
    def _pick_rule(entry: SecurityMatrixEntry) -> tuple[str, str, str, str]:
        if entry.is_exploitable and not entry.is_detectable:
            r = RemediationService.REMEDIATION_RULES["exploitable_undetected"]
        elif entry.is_exploitable and entry.is_detectable:
            r = RemediationService.REMEDIATION_RULES["exploitable_detected"]
        elif entry.is_present and not entry.is_exploitable:
            r = RemediationService.REMEDIATION_RULES["present_not_exploitable"]
        else:
            r = RemediationService.REMEDIATION_RULES["cve_default"]
        return r["action"], r["why"], r["example"], r["confidence"]

    @staticmethod
    def _build_summary(db: Session, entry: SecurityMatrixEntry) -> str:
        parts = []
        if entry.finding_id:
            finding = db.query(TrivyFinding).filter(
                TrivyFinding.finding_id == entry.finding_id
            ).first()
            if finding:
                parts.append(f"[{finding.severity.upper()}] {finding.cve_id} ({finding.package_name})")
        if entry.mitre_tactic_id:
            parts.append(f"MITRE {entry.mitre_tactic_id}")
        return " | ".join(parts) if parts else f"Security Matrix Entry #{entry.entry_id}"
