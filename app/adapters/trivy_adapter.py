import json
import subprocess
from pathlib import Path
from typing import List

from app.core.config import settings
from app.core.logging import get_logger
from app.models.trivy_finding import TrivyFinding

logger = get_logger(__name__)

_DEV_FIXTURE = Path("data/sample_outputs/trivy-fixture.json")

# Mapping of Trivy severity strings to normalised lowercase values
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
}


class TrivyAdapter:
    @staticmethod
    def scan(image_ref: str, run_id: int) -> List[TrivyFinding]:
        """Scan image_ref and return list of TrivyFinding objects (not yet persisted)."""
        if settings.dev_mode:
            logger.info("TrivyAdapter dev mode: reading fixture", extra={"run_id": run_id})
            raw = json.loads(_DEV_FIXTURE.read_text())
        else:
            raw = TrivyAdapter._run_trivy(image_ref)

        return TrivyAdapter._parse(raw, run_id)

    @staticmethod
    def is_blocking() -> bool:
        """Trivy findings never block the pipeline (Non-Blocking Rule §4.12.2)."""
        return False

    @staticmethod
    def _run_trivy(image_ref: str) -> dict:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", image_ref],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode not in (0, 1):  # 1 means vulnerabilities found, still valid
            raise RuntimeError(f"Trivy failed: {result.stderr}")
        return json.loads(result.stdout)

    @staticmethod
    def _parse(raw: dict, run_id: int) -> List[TrivyFinding]:
        findings: List[TrivyFinding] = []
        for result in raw.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                findings.append(
                    TrivyFinding(
                        run_id=run_id,
                        cve_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                        severity=_SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "unknown"),
                        package_name=vuln.get("PkgName", ""),
                        description=vuln.get("Description", "")[:2000],
                        fix_available=bool(vuln.get("FixedVersion")),
                    )
                )
        return findings
