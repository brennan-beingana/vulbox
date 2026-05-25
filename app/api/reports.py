import csv
import io
import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.remediation import Remediation
from app.models.run_summary import RunSummary
from app.models.security_matrix_entry import SecurityMatrixEntry
from app.models.trivy_finding import TrivyFinding
from app.models.art_test_result import ARTTestResult
from app.schemas.report import (
    ExecutiveSummarySchema,
    RemediationResponseSchema,
    ReportResponse,
    SecurityMatrixEntrySchema,
)
from app.services.run_service import RunService


def _load_executive_summary(db: Session, run_id: int) -> ExecutiveSummarySchema | None:
    row = db.query(RunSummary).filter(RunSummary.run_id == run_id).first()
    if row is None:
        return None
    try:
        priorities = json.loads(row.top_priorities or "[]")
    except json.JSONDecodeError:
        priorities = []
    return ExecutiveSummarySchema(
        headline=row.headline,
        overall_posture=row.overall_posture,
        top_priorities=[str(p) for p in priorities],
        confidence=row.confidence,
        source=row.source,
        generated_by=row.generated_by,
    )

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
        executive_summary=_load_executive_summary(db, run_id),
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
        remediations = (
            db.query(Remediation).filter(Remediation.run_id == run_id).all()
        )
        summary = _load_executive_summary(db, run_id)
        html = _render_pdf_html(run, matrix, remediations, summary)
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
        except Exception as exc:  # noqa: BLE001 — surface render failures cleanly
            return Response(
                content=f"PDF generation failed: {exc}",
                status_code=500,
                media_type="text/plain",
            )


def _render_pdf_html(run, matrix, remediations=None, summary=None) -> str:
    from html import escape as esc

    rows = "".join(
        f"<tr><td>{esc(e.mitre_tactic_id or '')}</td><td>{'Yes' if e.is_present else 'No'}</td>"
        f"<td>{'Yes' if e.is_exploitable else 'No'}</td>"
        f"<td>{'Yes' if e.is_detectable else 'No'}</td><td>{e.risk_score}</td></tr>"
        for e in matrix
    )

    summary_html = ""
    if summary is not None:
        priorities = "".join(f"<li>{esc(p)}</li>" for p in summary.top_priorities)
        badge = "AI-generated" if summary.generated_by == "llm" else "rule-based"
        summary_html = (
            f"<h2>Executive Summary <small>({badge})</small></h2>"
            f"<p class='headline'>{esc(summary.headline)}</p>"
            f"<p>{esc(summary.overall_posture)}</p>"
            f"<ul>{priorities}</ul>"
        )

    rem_html = ""
    if remediations:
        cards = "".join(
            f"<div class='rem'><h3>{esc(r.summary)} "
            f"<small>[{esc(r.confidence)} · {esc(r.generated_by)}]</small></h3>"
            f"<p><strong>Priority action:</strong> {esc(r.priority_action)}</p>"
            f"<p><strong>Why it matters:</strong> {esc(r.why_it_matters)}</p>"
            + (f"<pre>{esc(r.example_fix)}</pre>" if r.example_fix else "")
            + (
                "<p><strong>References:</strong><br>"
                + "<br>".join(esc(x) for x in r.references.splitlines() if x.strip())
                + "</p>"
                if r.references
                else ""
            )
            + "</div>"
            for r in remediations
        )
        rem_html = f"<h2>Remediation Actions</h2>{cards}"

    return f"""<!DOCTYPE html><html><head><style>
    body {{ font-family: sans-serif; margin: 2rem; color: #0f172a; }}
    h1 {{ color: #0f172a; }} table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
    th {{ background: #0f172a; color: white; }}
    .headline {{ font-size: 1.1rem; font-weight: bold; }}
    .rem {{ border: 1px solid #e2e8f0; border-radius: 6px; padding: 0.75rem; margin: 0.5rem 0; }}
    pre {{ background: #f1f5f9; padding: 0.5rem; white-space: pre-wrap; word-wrap: break-word; }}
    small {{ color: #64748b; font-weight: normal; }}
    </style></head><body>
    <h1>VulBox Security Report — {esc(run.project_name or '')}</h1>
    <p>Run ID: {run.id} | Status: {esc(run.status or '')} | Image: {esc(run.image_tag or '')}</p>
    {summary_html}
    <h2>Security Matrix</h2>
    <table><tr><th>MITRE Tactic</th><th>Present</th><th>Exploitable</th>
    <th>Detectable</th><th>Risk Score</th></tr>{rows}</table>
    {rem_html}
    </body></html>"""
