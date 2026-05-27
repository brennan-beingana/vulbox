import json
import subprocess
from pathlib import Path
from typing import List

from app.core.config import settings
from app.core.logging import get_logger
from app.models.trivy_finding import TrivyFinding
from app.services import epss

logger = get_logger(__name__)

_DEV_FIXTURE = settings.project_root / "data" / "sample_outputs" / "trivy-fixture.json"

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
        # Pass --timeout to Trivy itself (its own default is 5m, which huge
        # images like OWASP Juice Shop blow past) and give the subprocess a
        # little extra wall-clock so Trivy can exit cleanly before we kill it.
        scan_timeout = settings.trivy_timeout_secs
        cmd = [
            "trivy", "image", "--quiet",
            "--timeout", f"{scan_timeout}s",
            "--format", "json", image_ref,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_timeout + 60,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Trivy scan of {image_ref} exceeded {scan_timeout + 60}s. Large "
                "images (e.g. OWASP Juice Shop) need more: raise "
                "VULBOX_TRIVY_TIMEOUT_SECS, and pre-warm with "
                "`trivy image --download-db-only` + `docker pull` so the scan "
                "isn't also downloading the DB/image."
            ) from exc
        if result.returncode not in (0, 1):  # 1 means vulnerabilities found, still valid
            raise RuntimeError(
                f"Trivy failed (rc={result.returncode}): {result.stderr[-1000:]}"
            )
        return json.loads(result.stdout)

    @staticmethod
    def _parse(raw: dict, run_id: int) -> List[TrivyFinding]:
        findings: List[TrivyFinding] = []
        for result in raw.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
                # CweIDs is a list in real Trivy output (e.g. ["CWE-79"]); join
                # so the scan-time bridge can resolve techniques per finding.
                cwe_ids = ",".join(vuln.get("CweIDs") or [])
                findings.append(
                    TrivyFinding(
                        run_id=run_id,
                        cve_id=cve_id,
                        severity=_SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "unknown"),
                        package_name=vuln.get("PkgName", ""),
                        description=vuln.get("Description", "")[:2000],
                        fix_available=bool(vuln.get("FixedVersion")),
                        cwe_ids=cwe_ids,
                        epss_score=epss.score_for(cve_id),
                    )
                )
        return findings
