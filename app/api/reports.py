import csv
import io

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.remediation import Remediation
from app.models.security_matrix_entry import SecurityMatrixEntry
from app.models.trivy_finding import TrivyFinding
from app.models.art_test_result import ARTTestResult
from app.schemas.report import (
    RemediationResponseSchema,
    ReportResponse,
    SecurityMatrixEntrySchema,
)
from app.services.run_service import RunService

router = APIRouter(prefix="/reports", tags=["reporting"])


@router.get("/{run_id}", response_model=ReportResponse)
def get_report(run_id: int, db: Session = Depends(get_db)):
    run = RunService.get_run(db, run_id)

    matrix = (
        db.query(SecurityMatrixEntry)
        .filter(SecurityMatrixEntry.run_id == run_id)
        .all()
    )
    remediations = (
        db.query(Remediation).filter(Remediation.run_id == run_id).all()
    )
    trivy_count = (
        db.query(TrivyFinding).filter(TrivyFinding.run_id == run_id).count()
    )
    art_count = (
        db.query(ARTTestResult).filter(ARTTestResult.run_id == run_id).count()
    )

    return ReportResponse(
        run_id=run.id,
        project_name=run.project_name,
        image_tag=run.image_tag,
        status=run.status,
        trivy_findings_count=trivy_count,
        art_tests_count=art_count,
        remediations_count=len(remediations),
        security_matrix=[SecurityMatrixEntrySchema.model_validate(e) for e in matrix],
        remediations=[RemediationResponseSchema.model_validate(r) for r in remediations],
        created_at=run.created_at,
    )


@router.get("/{run_id}/export")
def export_report(
    run_id: int,
    format: str = Query(default="json", pattern="^(json|csv|pdf)$"),
    db: Session = Depends(get_db),
):
    run = RunService.get_run(db, run_id)
    matrix = (
        db.query(SecurityMatrixEntry)
        .filter(SecurityMatrixEntry.run_id == run_id)
        .all()
    )

    if format == "json":
        # Reuse the standard report endpoint
        from fastapi.encoders import jsonable_encoder
        report = get_report(run_id, db)
        return jsonable_encoder(report)

    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            ["entry_id", "mitre_tactic_id", "is_present", "is_exploitable",
             "is_detectable", "risk_score", "finding_id", "test_result_id"]
        )
        for e in matrix:
            writer.writerow([
                e.entry_id, e.mitre_tactic_id, e.is_present, e.is_exploitable,
                e.is_detectable, e.risk_score, e.finding_id, e.test_result_id,
            ])
        buf.seek(0)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=vulbox-report-{run_id}.csv"},
        )

    if format == "pdf":
        html = _render_pdf_html(run, matrix)
        try:
            import weasyprint
            pdf_bytes = weasyprint.HTML(string=html).write_pdf()
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=vulbox-report-{run_id}.pdf"},
            )
        except ImportError:
            return Response(
                content="PDF export requires weasyprint. Install it with: pip install weasyprint",
                status_code=501,
                media_type="text/plain",
            )


def _render_pdf_html(run, matrix) -> str:
    rows = "".join(
        f"<tr><td>{e.mitre_tactic_id}</td><td>{'Yes' if e.is_present else 'No'}</td>"
        f"<td>{'Yes' if e.is_exploitable else 'No'}</td>"
        f"<td>{'Yes' if e.is_detectable else 'No'}</td><td>{e.risk_score}</td></tr>"
        for e in matrix
    )
    return f"""<!DOCTYPE html><html><head><style>
    body {{ font-family: sans-serif; margin: 2rem; }}
    h1 {{ color: #0f172a; }} table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
    th {{ background: #0f172a; color: white; }}
    </style></head><body>
    <h1>VulBox Security Report — {run.project_name}</h1>
    <p>Run ID: {run.id} | Status: {run.status} | Image: {run.image_tag}</p>
    <h2>Security Matrix</h2>
    <table><tr><th>MITRE Tactic</th><th>Present</th><th>Exploitable</th>
    <th>Detectable</th><th>Risk Score</th></tr>{rows}</table>
    </body></html>"""
