from sqlalchemy.orm import Session

from app.models.correlated_finding import CorrelatedFinding
from app.models.finding import Finding
from app.models.remediation import Remediation


class RemediationService:
    """Generate rule-based remediation guidance from correlated findings."""

    # Remediation rules: (asset_type, rule_id_pattern) → (action, why, example, confidence)
    REMEDIATION_RULES = {
        # CVE-based (Trivy findings)
        "cve": {
            "action": "Upgrade vulnerable package to fixed version",
            "why": "Known vulnerability with documented exploit or high attack surface",
            "example": "Run: apt-get update && apt-get upgrade -y",
            "confidence": "high",
        },
        # Runtime behaviors (Falco findings)
        "Terminal shell in container": {
            "action": "Remove interactive shell access from container image",
            "why": "Interactive shells increase attack surface and enable lateral movement",
            "example": "Remove bash/sh from base image or use distroless image",
            "confidence": "high",
        },
        "Write below root dir": {
            "action": "Apply read-only root filesystem or restrict write permissions",
            "why": "Unauthorized writes to system directories indicate compromise or misconfiguration",
            "example": "Set readOnlyRootFilesystem: true in container security context",
            "confidence": "high",
        },
        # Validation behaviors (Atomic findings)
        "Validation: success": {
            "action": "Review and mitigate confirmed technique",
            "why": "Atomic validation confirmed that the technique is exploitable",
            "example": "Implement specific defense controls for this MITRE technique",
            "confidence": "critical",
        },
    }

    @staticmethod
    def generate_remediations(db: Session, run_id: int) -> list[Remediation]:
        """Generate remediation for all correlated findings in a run."""
        correlated_findings = db.query(CorrelatedFinding).filter(
            CorrelatedFinding.run_id == run_id
        ).all()
        
        remediations = []
        
        for correlated in correlated_findings:
            # Get primary finding for details
            primary_finding = db.query(Finding).filter(
                Finding.id == correlated.main_finding_id
            ).first()
            
            if not primary_finding:
                continue
            
            # Determine remediation rule
            action, why, example, confidence = RemediationService._get_rule(
                primary_finding
            )
            
            # Create summary
            summary = f"[{primary_finding.severity.upper()}] {primary_finding.title}"
            
            # Build remediation record
            remediation = Remediation(
                run_id=run_id,
                correlated_finding_id=correlated.id,
                summary=summary,
                priority_action=action,
                why_it_matters=why,
                example_fix=example,
                confidence=confidence,
                source="rule-based",
            )
            
            db.add(remediation)
            remediations.append(remediation)
        
        db.commit()
        return remediations

    @staticmethod
    def _get_rule(finding: Finding) -> tuple[str, str, str, str]:
        """
        Determine remediation rule for a finding.
        Returns: (action, why_it_matters, example_fix, confidence)
        """
        # Check by finding type
        if finding.source_tool == "trivy":
            # CVE remediation
            rule = RemediationService.REMEDIATION_RULES.get("cve")
            if rule:
                # Customize action with fixed version if available
                fixed_version = finding.evidence_json.get("fixed_version")
                action = rule["action"]
                if fixed_version:
                    action = f"{action} (to {fixed_version})"
                
                return (
                    action,
                    rule["why"],
                    rule["example"],
                    rule["confidence"],
                )
        
        elif finding.source_tool == "falco":
            # Runtime behavior remediation
            rule_name = finding.rule_or_cve_id
            rule = RemediationService.REMEDIATION_RULES.get(rule_name)
            if rule:
                return (
                    rule["action"],
                    rule["why"],
                    rule["example"],
                    rule["confidence"],
                )
            else:
                # Generic Falco remediation
                return (
                    "Review runtime policy and container security context",
                    "Unexpected runtime behavior indicates potential compromise or misconfiguration",
                    "Apply principle of least privilege: disable unnecessary capabilities",
                    "medium",
                )
        
        elif finding.source_tool == "atomic":
            # Validation-based remediation
            status = finding.evidence_json.get("status", "unknown")
            if status == "success":
                rule = RemediationService.REMEDIATION_RULES.get("Validation: success")
                if rule:
                    return (
                        rule["action"],
                        rule["why"],
                        rule["example"],
                        rule["confidence"],
                    )
            
            return (
                "Review validation results and apply defenses",
                "Validation test execution provides insight into exploitability",
                "Consult MITRE ATT&CK framework for mitigation strategies",
                "medium",
            )
        
        # Fallback
        return (
            "Review finding and apply appropriate controls",
            "Security assessment identified potential issue",
            "Consult security best practices for this asset type",
            "low",
        )
