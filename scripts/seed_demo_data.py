"""Pre-populate the VulBox DB with completed runs so the Reports page is alive
on first demo load.

Three runs, each painting a different cell of the Security Matrix:
- Critical: exploited + undetected
- High:     exploited + detected
- Medium:   present but not exploited

Writes directly to SQLAlchemy — bypasses the orchestrator on purpose. The
goal is screen-state, not pipeline exercise (`scripts/demo.py` already does
the latter).

Usage:
    python scripts/seed_demo_data.py             # append seed runs
    python scripts/seed_demo_data.py --reset     # drop DB first
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Make `app` importable when run from anywhere.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.core.database import Base, SessionLocal, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.art_test_result import ARTTestResult  # noqa: E402
from app.models.falco_alert import FalcoAlert  # noqa: E402
from app.models.remediation import Remediation  # noqa: E402
from app.models.run import AssessmentRun  # noqa: E402
from app.models.security_matrix_entry import SecurityMatrixEntry  # noqa: E402
from app.models.trivy_finding import TrivyFinding  # noqa: E402
from app.models.user import User  # noqa: E402

DEMO_USER_EMAIL = "demo@vulbox.local"
DEMO_USER_PASSWORD = "demo-password-1234"


def ensure_demo_user(db) -> User:
    user = db.query(User).filter(User.email == DEMO_USER_EMAIL).first()
    if user:
        return user
    user = User(
        email=DEMO_USER_EMAIL,
        hashed_password=hash_password(DEMO_USER_PASSWORD),
        role="provider",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _seed_run(
    db,
    project_name: str,
    cve_id: str,
    severity: str,
    package: str,
    technique_id: str,
    exploited: bool,
    detected: bool,
    risk_score: int,
    remediation_summary: str,
    remediation_action: str,
) -> AssessmentRun:
    now = datetime.utcnow()
    run = AssessmentRun(
        project_name=project_name,
        repo_url="https://github.com/vulbox/demo-target",
        branch="main",
        commit_sha="seed0000",
        image_name="vulbox-demo",
        image_tag="seed",
        status="COMPLETE",
        submitted_by=DEMO_USER_EMAIL,
        consent_granted=True,
        started_at=now - timedelta(minutes=5),
        completed_at=now,
        created_at=now - timedelta(minutes=5),
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    finding = TrivyFinding(
        run_id=run.id,
        cve_id=cve_id,
        severity=severity,
        package_name=package,
        description=f"Seeded finding for {cve_id} in {package}.",
        fix_available=True,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    test = ARTTestResult(
        run_id=run.id,
        mitre_test_id=technique_id,
        exploited=exploited,
        crash_occurred=False,
        executed_at=now - timedelta(minutes=2),
    )
    db.add(test)
    db.commit()
    db.refresh(test)

    entry = SecurityMatrixEntry(
        run_id=run.id,
        finding_id=finding.finding_id,
        test_result_id=test.test_result_id,
        is_present=True,
        is_exploitable=exploited,
        is_detectable=detected,
        mitre_tactic_id=technique_id,
        risk_score=risk_score,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    if detected:
        db.add(
            FalcoAlert(
                run_id=run.id,
                test_result_id=test.test_result_id,
                rule_triggered="Terminal shell in container",
                severity="high",
                syscall_context="execve /bin/sh from container PID 1",
                timestamp=now - timedelta(minutes=2),
                detected=True,
            )
        )

    db.add(
        Remediation(
            run_id=run.id,
            matrix_entry_id=entry.entry_id,
            summary=remediation_summary,
            priority_action=remediation_action,
            why_it_matters=f"{technique_id} on {package} mapped from {cve_id}.",
            example_fix=f"# pin {package} to a fixed version\n# see {cve_id} advisory",
            confidence="high",
            source="seed",
            generated_by="static",
            references=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )
    )
    db.commit()
    return run


def seed(reset: bool = False) -> None:
    if reset:
        Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        user = ensure_demo_user(db)
        print(f"demo user: {user.email}  (password: {DEMO_USER_PASSWORD})")

        runs = [
            _seed_run(
                db,
                project_name="payments-api",
                cve_id="CVE-2021-44228",
                severity="critical",
                package="log4j",
                technique_id="T1059",
                exploited=True,
                detected=False,
                risk_score=70,
                remediation_summary="Upgrade log4j to 2.17.1+",
                remediation_action="Bump log4j-core in pom.xml and rebuild image.",
            ),
            _seed_run(
                db,
                project_name="auth-service",
                cve_id="CVE-2019-5736",
                severity="high",
                package="runc",
                technique_id="T1611",
                exploited=True,
                detected=True,
                risk_score=55,
                remediation_summary="Update runc to >=1.0.0-rc7",
                remediation_action="apt-get upgrade docker-ce containerd.io",
            ),
            _seed_run(
                db,
                project_name="storage-gateway",
                cve_id="CVE-2020-15257",
                severity="medium",
                package="containerd",
                technique_id="T1543.002",
                exploited=False,
                detected=False,
                risk_score=20,
                remediation_summary="Patch containerd to 1.3.9+",
                remediation_action="Restart containerd with --host=unix-only after upgrade.",
            ),
        ]
        for r in runs:
            print(f"  run #{r.id:>3}  {r.project_name:<22}  status={r.status}")
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset", action="store_true", help="drop and recreate all tables first"
    )
    args = parser.parse_args()
    seed(reset=args.reset)


if __name__ == "__main__":
    main()
