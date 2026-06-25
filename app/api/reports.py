import csv
import io
import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user, get_current_user_flexible
from app.models.detected_technology import DetectedTechnology
from app.models.remediation import Remediation
from app.models.run_summary import RunSummary
from app.models.security_matrix_entry import SecurityMatrixEntry
from app.models.trivy_finding import TrivyFinding
from app.models.art_test_result import ARTTestResult
from app.models.user import User
from app.schemas.report import (
    CoverageSchema,
    DetectedTechnologySchema,
    ExecutiveSummarySchema,
    RemediationResponseSchema,
    ReportResponse,
    SecurityMatrixEntrySchema,
)
from app.services.run_service import RunService


# Critical → low ordering. Higher rank sorts first; entries with no motivating
# finding (proactive/fallback) fall to the bottom of their risk band.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _matrix_schema(entry: SecurityMatrixEntry, findings_by_id: dict) -> SecurityMatrixEntrySchema:
    """Enrich a matrix entry with its motivating CVE id, severity, EPSS, provenance."""
    from app.adapters.art_adapter import _CVE_TECHNIQUE_MAP

    schema = SecurityMatrixEntrySchema.model_validate(entry)
    finding = findings_by_id.get(entry.finding_id)
    if finding is not None:
        schema.cve_id = finding.cve_id
        schema.severity = (getattr(finding, "severity", None) or "unknown").lower()
        schema.epss_score = finding.epss_score
        # Direct CVE→technique mapping vs. the coarser CWE-bridge fallback.
        schema.match_source = (
            "cve-map" if finding.cve_id in _CVE_TECHNIQUE_MAP else "cwe-bridge"
        )
    return schema


def _entry_sort_key(entry: SecurityMatrixEntry, findings_by_id: dict) -> tuple:
    """Sort key for critical→low ordering: (severity_rank, risk_score), desc."""
    finding = findings_by_id.get(entry.finding_id)
    sev = (getattr(finding, "severity", None) or "unknown").lower() if finding is not None else "unknown"
    return (_SEVERITY_RANK.get(sev, 0), entry.risk_score or 0)


def _rem_schema(rem, entries_by_id: dict, findings_by_id: dict) -> RemediationResponseSchema:
    """Enrich a remediation with its matrix entry's severity + risk for filtering."""
    schema = RemediationResponseSchema.model_validate(rem)
    entry = entries_by_id.get(rem.matrix_entry_id)
    if entry is not None:
        schema.risk_score = entry.risk_score
        finding = findings_by_id.get(entry.finding_id)
        if finding is not None:
            schema.severity = (getattr(finding, "severity", None) or "unknown").lower()
    return schema


def _coverage(findings: list, matrix: list) -> CoverageSchema:
    """Distinct detected CVEs vs. distinct CVEs that got an exploitability row."""
    detected = {f.cve_id for f in findings}
    by_id = {f.finding_id: f for f in findings}
    tested = {
        by_id[e.finding_id].cve_id
        for e in matrix
        if e.finding_id is not None and e.finding_id in by_id
    }
    return CoverageSchema(detected_cves=len(detected), tested_cves=len(tested))


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
def get_report(
    run_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    run = RunService.authorize(RunService.get_run(db, run_id), current_user)

    findings = db.query(TrivyFinding).filter(TrivyFinding.run_id == run_id).all()
    findings_by_id = {f.finding_id: f for f in findings}

    matrix = (
        db.query(SecurityMatrixEntry)
        .filter(SecurityMatrixEntry.run_id == run_id)
        .all()
    )
    # Critical → low: severity band first, then risk score within it.
    matrix.sort(key=lambda e: _entry_sort_key(e, findings_by_id), reverse=True)

    remediations = (
        db.query(Remediation).filter(Remediation.run_id == run_id).all()
    )
    # Remediation cards follow the same critical→low order as the matrix, and
    # carry their entry's severity/risk so the frontend can filter them.
    entries_by_id = {e.entry_id: e for e in matrix}

    def _rem_sort_key(r: Remediation) -> tuple:
        e = entries_by_id.get(r.matrix_entry_id)
        return _entry_sort_key(e, findings_by_id) if e is not None else (0, 0)

    remediations.sort(key=_rem_sort_key, reverse=True)
    trivy_count = len(findings)
    art_count = (
        db.query(ARTTestResult).filter(ARTTestResult.run_id == run_id).count()
    )
    technologies = (
        db.query(DetectedTechnology)
        .filter(DetectedTechnology.run_id == run_id)
        .order_by(DetectedTechnology.confidence.desc())
        .all()
    )

    return ReportResponse(
        run_id=run.id,
        project_name=run.project_name,
        image_tag=run.image_tag,
        status=run.status,
        trivy_findings_count=trivy_count,
        art_tests_count=art_count,
        remediations_count=len(remediations),
        detected_technologies=[DetectedTechnologySchema.model_validate(t) for t in technologies],
        security_matrix=[_matrix_schema(e, findings_by_id) for e in matrix],
        remediations=[
            _rem_schema(r, entries_by_id, findings_by_id) for r in remediations
        ],
        executive_summary=_load_executive_summary(db, run_id),
        coverage=_coverage(findings, matrix),
        created_at=run.created_at,
    )


@router.get("/{run_id}/export")
def export_report(
    run_id: int,
    format: str = Query(default="json", pattern="^(json|csv|pdf)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_flexible),
):
    run = RunService.authorize(RunService.get_run(db, run_id), current_user)
    findings = db.query(TrivyFinding).filter(TrivyFinding.run_id == run_id).all()
    findings_by_id = {f.finding_id: f for f in findings}
    matrix = (
        db.query(SecurityMatrixEntry)
        .filter(SecurityMatrixEntry.run_id == run_id)
        .all()
    )
    matrix.sort(key=lambda e: _entry_sort_key(e, findings_by_id), reverse=True)

    if format == "json":
        # Reuse the standard report endpoint (already authorized above).
        from fastapi.encoders import jsonable_encoder
        report = get_report(run_id, db, current_user)
        return jsonable_encoder(report)

    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            ["entry_id", "mitre_tactic_id", "cve_id", "severity", "epss_score",
             "is_present", "is_exploitable", "is_detectable", "risk_score",
             "finding_id", "test_result_id"]
        )
        for e in matrix:
            f = findings_by_id.get(e.finding_id)
            writer.writerow([
                e.entry_id, e.mitre_tactic_id,
                f.cve_id if f else "", f.severity if f else "",
                f.epss_score if f else "",
                e.is_present, e.is_exploitable,
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
        entries_by_id = {e.entry_id: e for e in matrix}
        remediations.sort(
            key=lambda r: (
                _entry_sort_key(entries_by_id[r.matrix_entry_id], findings_by_id)
                if r.matrix_entry_id in entries_by_id else (0, 0)
            ),
            reverse=True,
        )
        summary = _load_executive_summary(db, run_id)
        technologies = (
            db.query(DetectedTechnology)
            .filter(DetectedTechnology.run_id == run_id)
            .order_by(DetectedTechnology.confidence.desc())
            .all()
        )
        coverage = _coverage(findings, matrix)
        html = _render_pdf_html(
            run, matrix, remediations, summary, technologies, findings_by_id, coverage
        )
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


# Palette mirrors the web design system (frontend/src/styles.css) so the PDF
# matches the dashboard.
_PDF_FONT = "-apple-system, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
_PDF_MONO = "'SF Mono', 'DejaVu Sans Mono', 'Consolas', monospace"
_CONF_ACCENT = {"critical": "#dc2626", "high": "#d97706", "medium": "#2563eb", "low": "#059669"}
# (background, text) for confidence/AI badges.
_CONF_BADGE = {
    "critical": ("#fee2e2", "#dc2626"),
    "high": ("#fef3c7", "#d97706"),
    "medium": ("#dbeafe", "#2563eb"),
    "low": ("#d1fae5", "#059669"),
}


def _risk_color(score: int) -> str:
    if score >= 40:
        return "#dc2626"
    if score >= 25:
        return "#ea580c"
    if score >= 15:
        return "#d97706"
    return "#059669"


def _render_pdf_html(
    run, matrix, remediations=None, summary=None, technologies=None,
    findings_by_id=None, coverage=None,
) -> str:
    from html import escape as esc

    findings_by_id = findings_by_id or {}

    def _badge(text: str, bg: str, fg: str) -> str:
        return (
            f"<span style='display:inline-block;background:{bg};color:{fg};"
            "font-size:8px;font-weight:700;letter-spacing:0.4px;text-transform:uppercase;"
            f"padding:2px 7px;border-radius:9999px;'>{esc(text)}</span>"
        )

    def _conf_badge(conf: str) -> str:
        bg, fg = _CONF_BADGE.get((conf or "").lower(), ("#f3f4f6", "#6b7280"))
        return _badge(conf or "n/a", bg, fg)

    # ---- summary stat strip (computed from available data) ----
    total = len(matrix)
    exploitable = sum(1 for e in matrix if e.is_exploitable)
    rem_count = len(remediations or [])
    max_risk = max((e.risk_score for e in matrix), default=0)

    def _stat(label: str, value: str, color: str = "#111827") -> str:
        return (
            "<td style='width:25%;border:1px solid #e4e8f0;border-radius:12px;"
            "padding:10px 14px;'>"
            f"<div style='font-size:8px;font-weight:700;letter-spacing:0.6px;"
            f"text-transform:uppercase;color:#9ca3af;'>{esc(label)}</div>"
            f"<div style='font-size:22px;font-weight:800;color:{color};"
            f"padding-top:4px;'>{value}</div></td>"
        )

    stats_html = (
        "<table style='width:100%;border-collapse:separate;border-spacing:8px;"
        "margin:4px 0 18px -8px;'><tr>"
        + _stat("Matrix Entries", str(total))
        + _stat("Exploitable", str(exploitable), "#dc2626" if exploitable else "#111827")
        + _stat("Remediations", str(rem_count))
        + _stat("Max Risk", f"{max_risk}<span style='font-size:12px;font-weight:500;color:#9ca3af;'>/75</span>", _risk_color(max_risk))
        + "</tr></table>"
    )

    # ---- detected tech stack ----
    tech_html = ""
    if technologies:
        chips = "".join(
            "<span style='display:inline-block;font-size:10px;color:#4f46e5;"
            "background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.18);"
            "border-radius:6px;padding:3px 9px;margin:0 6px 6px 0;'>"
            f"{esc(t.name)}"
            + (f"<span style='color:#9ca3af;'> {esc(t.version)}</span>" if t.version else "")
            + "</span>"
            for t in technologies
        )
        tech_html = (
            "<div class='section-label'>Detected Stack</div>"
            f"<div style='margin-bottom:4px;'>{chips}</div>"
        )

    # ---- executive summary hero ----
    summary_html = ""
    if summary is not None:
        ai = _badge("AI-generated", "#dbeafe", "#2563eb") if summary.generated_by == "llm" else _badge("rule-based", "#f3f4f6", "#6b7280")
        priorities = ""
        if summary.top_priorities:
            items = "".join(
                f"<li style='margin-bottom:6px;'>{esc(p)}</li>" for p in summary.top_priorities
            )
            priorities = (
                "<div style='font-size:8px;font-weight:700;letter-spacing:0.5px;"
                "text-transform:uppercase;color:#9ca3af;margin:12px 0 4px;'>Top priorities</div>"
                f"<ol style='margin:0;padding-left:18px;font-size:11px;color:#111827;line-height:1.5;'>{items}</ol>"
            )
        summary_html = (
            "<div class='section-label'>Executive Summary " + ai + "</div>"
            "<div class='exec'>"
            f"<div style='font-size:13px;font-weight:700;color:#111827;line-height:1.4;margin-bottom:6px;'>"
            f"{esc(summary.headline)} &nbsp; {_conf_badge(summary.confidence)}</div>"
            f"<div style='font-size:11px;color:#4b5563;line-height:1.6;'>{esc(summary.overall_posture)}</div>"
            f"{priorities}</div>"
        )

    # ---- security matrix ----
    def _yn(val: bool, color_yes: str = "#dc2626", color_no: str = "#9ca3af") -> str:
        c = color_yes if val else color_no
        return f"<span style='font-weight:700;color:{c};'>{'Yes' if val else 'No'}</span>"

    def _epss_cell(score) -> str:
        if score is None:
            return "<span style='color:#9ca3af;'>—</span>"
        # EPSS is a 0–1 probability; show as a percentage, bold when elevated.
        weight = "700" if score >= 0.10 else "400"
        color = "#dc2626" if score >= 0.50 else "#111827"
        return f"<span style='font-weight:{weight};color:{color};'>{score * 100:.1f}%</span>"

    def _sev_cell(sev) -> str:
        if not sev:
            return "<span style='color:#9ca3af;'>—</span>"
        color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#059669"}.get(
            sev.lower(), "#6b7280"
        )
        return (
            f"<span style='display:inline-block;background:{color};color:#fff;font-size:8px;"
            f"font-weight:700;text-transform:uppercase;padding:2px 7px;border-radius:9999px;'>{esc(sev)}</span>"
        )

    rows = ""
    for e in matrix:
        f = findings_by_id.get(e.finding_id)
        cve = f.cve_id if f else None
        sev = f.severity if f else None
        epss = f.epss_score if f else None
        rows += (
            "<tr>"
            f"<td><span style='font-family:{_PDF_MONO};font-size:10px;background:#f0f2f8;"
            f"border:1px solid #e4e8f0;border-radius:5px;padding:2px 6px;'>{esc(e.mitre_tactic_id or '—')}</span></td>"
            f"<td><span style='font-family:{_PDF_MONO};font-size:9.5px;color:#4b5563;'>{esc(cve or '—')}</span></td>"
            f"<td>{_sev_cell(sev)}</td>"
            f"<td>{_epss_cell(epss)}</td>"
            f"<td>{_yn(e.is_present, '#111827', '#9ca3af')}</td>"
            f"<td>{_yn(e.is_exploitable)}</td>"
            f"<td>{_yn(e.is_detectable, '#059669', '#dc2626')}</td>"
            f"<td><span style='display:inline-block;background:{_risk_color(e.risk_score)};color:#fff;"
            f"font-size:10px;font-weight:800;padding:2px 8px;border-radius:9999px;'>{e.risk_score}/75</span></td>"
            "</tr>"
        )

    # Coverage caption — directly answers "how many detected CVEs got an
    # exploitability verdict".
    coverage_html = ""
    if coverage is not None:
        coverage_html = (
            "<div style='font-size:10px;color:#6b7280;margin:0 0 8px;'>"
            f"Exploitability tested for <b style='color:#111827;'>{coverage.tested_cves}</b> "
            f"of <b style='color:#111827;'>{coverage.detected_cves}</b> detected CVEs.</div>"
        )

    # ---- remediation cards ----
    rem_html = ""
    if remediations:
        def _field(label: str, value_html: str) -> str:
            return (
                "<div style='margin:6px 0;'>"
                f"<div style='font-size:8px;font-weight:700;letter-spacing:0.5px;"
                f"text-transform:uppercase;color:#9ca3af;margin-bottom:2px;'>{esc(label)}</div>"
                f"<div style='font-size:11px;color:#4b5563;line-height:1.55;'>{value_html}</div></div>"
            )

        cards = []
        for r in remediations:
            accent = _CONF_ACCENT.get((r.confidence or "").lower(), "#e4e8f0")
            ai = _badge("AI", "#dbeafe", "#2563eb") if r.generated_by == "llm" else _badge("rule", "#f3f4f6", "#6b7280")
            body = (
                _field("Priority action", esc(r.priority_action))
                + _field("Why it matters", esc(r.why_it_matters))
            )
            if r.example_fix:
                body += _field(
                    "Example fix",
                    f"<pre style='font-family:{_PDF_MONO};font-size:9.5px;background:#f8fafc;"
                    "border:1px solid #e4e8f0;border-radius:6px;padding:8px 10px;white-space:pre-wrap;"
                    f"word-wrap:break-word;line-height:1.5;margin:2px 0 0;'>{esc(r.example_fix)}</pre>",
                )
            if r.references:
                chips = "".join(
                    f"<span style='display:inline-block;font-size:9px;color:#4f46e5;"
                    "background:rgba(99,102,241,0.08);border-radius:5px;padding:2px 6px;"
                    f"margin:2px 4px 0 0;'>{esc(x)}</span>"
                    for x in r.references.splitlines()
                    if x.strip()
                )
                if chips:
                    body += _field("References", chips)
            cards.append(
                f"<div class='rem' style='border-left:3px solid {accent};'>"
                "<div style='margin-bottom:6px;'>"
                f"<span style='font-size:12px;font-weight:700;color:#111827;'>{esc(r.summary)}</span> &nbsp; "
                f"{ai} {_conf_badge(r.confidence)}</div>"
                f"{body}</div>"
            )
        rem_html = "<div class='section-label'>Remediation Actions</div>" + "".join(cards)

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    @page {{ size: A4; margin: 1.6cm; }}
    body {{ font-family: {_PDF_FONT}; color: #111827; font-size: 11px; line-height: 1.5; }}
    h1 {{ font-size: 19px; font-weight: 800; letter-spacing: -0.4px; margin: 0 0 4px; }}
    .meta {{ margin: 0 0 16px; }}
    .chip {{ display: inline-block; font-size: 9px; font-weight: 600; color: #4b5563;
             background: #f0f2f8; border: 1px solid #e4e8f0; padding: 3px 9px;
             border-radius: 9999px; margin-right: 4px; }}
    .chip b {{ color: #9ca3af; font-weight: 700; text-transform: uppercase; font-size: 8px; }}
    .chip code {{ font-family: {_PDF_MONO}; font-size: 9px; color: #111827; }}
    .section-label {{ font-size: 10px; font-weight: 700; text-transform: uppercase;
                      letter-spacing: 0.8px; color: #9ca3af; margin: 20px 0 8px;
                      border-bottom: 1px solid #e4e8f0; padding-bottom: 6px; }}
    .exec {{ background: #f6f7fe; border: 1px solid #e4e8f0; border-radius: 12px;
             padding: 14px 16px; page-break-inside: avoid; }}
    table.matrix {{ width: 100%; border-collapse: collapse; }}
    table.matrix th {{ background: #0b1120; color: #94a3b8; font-size: 9px; font-weight: 700;
                       text-transform: uppercase; letter-spacing: 0.6px; text-align: left;
                       padding: 8px 10px; }}
    table.matrix td {{ padding: 8px 10px; border-bottom: 1px solid #f0f2f8; font-size: 11px; }}
    .rem {{ border: 1px solid #e4e8f0; border-radius: 10px; padding: 12px 14px;
            margin-bottom: 9px; page-break-inside: avoid; }}
    </style></head><body>
    <h1>VulBox Security Report — {esc(run.project_name or '')}</h1>
    <div class="meta">
      <span class="chip"><b>Run</b> #{run.id}</span>
      <span class="chip"><b>Image</b> <code>{esc(run.image_tag or '')}</code></span>
      <span class="chip"><b>Status</b> {esc(run.status or '')}</span>
    </div>
    {stats_html}
    {tech_html}
    {summary_html}
    <div class="section-label">Security Matrix</div>
    {coverage_html}
    <table class="matrix"><tr><th>MITRE Tactic</th><th>CVE</th><th>Severity</th><th>EPSS</th><th>Present</th>
    <th>Exploitable</th><th>Detectable</th><th>Risk Score</th></tr>{rows}</table>
    {rem_html}
    </body></html>"""
