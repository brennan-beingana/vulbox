"""Run-level executive summary.

Synthesises every SecurityMatrixEntry for a run into a short, prioritised
narrative — the "what do I fix first" view that sits above the per-entry
remediation cards. One Gemini call per run; on any failure (disabled, no key,
API error, malformed JSON) it falls back to a templated summary built purely
from the matrix counts, so the report always carries a summary.
"""
from __future__ import annotations

import json
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.run_summary import RunSummary
from app.models.security_matrix_entry import SecurityMatrixEntry
from app.models.trivy_finding import TrivyFinding
from app.services.llm_provider import GeminiProvider

logger = get_logger(__name__)

_SYSTEM_PROMPT = """You are a security lead briefing an engineering team on the results of an automated container assessment. You will be given aggregate statistics and the highest-risk findings.

Produce an executive summary as STRICT JSON matching this schema (no prose, no code fences):

{
  "headline": string,             // one sentence, ≤200 chars, overall verdict
  "overall_posture": string,      // ≤600 chars, plain-language risk assessment
  "top_priorities": [string],     // 1–5 imperative items, most urgent first
  "confidence": "critical"|"high"|"medium"|"low"
}

Rules:
- Prioritise by risk: exploitable-and-undetected findings come first.
- Be concrete and reference the actual counts/CVEs you are given.
- If there are no findings, say the image looks clean and recommend keeping scanning in CI.
- Output valid JSON only."""

_SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {
        "headline": {"type": "string"},
        "overall_posture": {"type": "string"},
        "top_priorities": {"type": "array", "items": {"type": "string"}},
        "confidence": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
        },
    },
    "required": ["headline", "overall_posture", "top_priorities"],
}


class RunSummaryService:
    """Generate (and persist) one RunSummary per run."""

    @staticmethod
    def is_enabled() -> bool:
        return (
            settings.llm_remediation_enabled
            and settings.llm_exec_summary_enabled
            and bool(settings.gemini_api_key)
        )

    @staticmethod
    def generate_summary(db: Session, run_id: int) -> RunSummary:
        entries = (
            db.query(SecurityMatrixEntry)
            .filter(SecurityMatrixEntry.run_id == run_id)
            .order_by(SecurityMatrixEntry.risk_score.desc())
            .all()
        )
        stats = _compute_stats(db, entries)

        payload: Optional[dict] = None
        if RunSummaryService.is_enabled():
            payload = GeminiProvider.generate_json(
                _SYSTEM_PROMPT, _format_prompt(stats), _SUMMARY_SCHEMA
            )

        if payload and _valid(payload):
            summary = RunSummary(
                run_id=run_id,
                headline=str(payload["headline"])[:300],
                overall_posture=str(payload["overall_posture"])[:1000],
                top_priorities=json.dumps(
                    [str(p) for p in (payload.get("top_priorities") or [])][:5]
                ),
                confidence=str(payload.get("confidence", "medium")).lower(),
                source="gemini",
                generated_by="llm",
            )
        else:
            summary = _templated_summary(run_id, stats)

        # One summary per run — replace any prior row (e.g. on a rebuild cycle).
        db.query(RunSummary).filter(RunSummary.run_id == run_id).delete()
        db.add(summary)
        db.commit()
        return summary


# ---- helpers --------------------------------------------------------------


def _compute_stats(db: Session, entries: List[SecurityMatrixEntry]) -> dict:
    exploitable = [e for e in entries if e.is_exploitable]
    undetected = [e for e in entries if e.is_exploitable and not e.is_detectable]
    top = entries[:5]
    top_lines: List[str] = []
    for e in top:
        cve = ""
        if e.finding_id:
            f = (
                db.query(TrivyFinding)
                .filter(TrivyFinding.finding_id == e.finding_id)
                .first()
            )
            if f:
                cve = f" [{(f.severity or '').upper()}] {f.cve_id}"
        top_lines.append(
            f"{e.mitre_tactic_id or 'n/a'}{cve} — risk {e.risk_score}, "
            f"exploitable={e.is_exploitable}, detected={e.is_detectable}"
        )
    return {
        "total": len(entries),
        "exploitable": len(exploitable),
        "undetected": len(undetected),
        "max_risk": max((e.risk_score for e in entries), default=0),
        "top_lines": top_lines,
    }


def _format_prompt(s: dict) -> str:
    top = "\n".join(f"- {line}" for line in s["top_lines"]) or "(no findings)"
    return (
        f"Total matrix entries: {s['total']}\n"
        f"Exploitable: {s['exploitable']}\n"
        f"Exploitable AND undetected: {s['undetected']}\n"
        f"Highest risk score (0–75): {s['max_risk']}\n"
        f"Top findings by risk:\n{top}\n\n"
        "Produce the executive summary JSON now."
    )


def _valid(payload: dict) -> bool:
    required = {"headline", "overall_posture", "top_priorities"}
    return isinstance(payload, dict) and required.issubset(payload.keys())


def _templated_summary(run_id: int, s: dict) -> RunSummary:
    """Deterministic fallback built from the counts — no LLM."""
    if s["total"] == 0:
        headline = "No security-matrix findings recorded for this run."
        posture = "The assessment produced no matrix entries. Keep Trivy and the runtime monitor in CI to catch regressions."
        priorities = ["Keep automated scanning enabled in CI."]
        confidence = "low"
    else:
        headline = (
            f"{s['total']} findings; {s['exploitable']} exploitable, "
            f"{s['undetected']} exploitable without detection."
        )
        posture = (
            f"Highest risk score is {s['max_risk']}/75. "
            f"{s['undetected']} finding(s) are both exploitable and undetected — "
            "these are the most urgent because an attack would succeed silently."
            if s["undetected"]
            else f"Highest risk score is {s['max_risk']}/75. Exploitable findings are "
            "currently caught by runtime detection; patch them and keep the rules active."
        )
        priorities = []
        if s["undetected"]:
            priorities.append(
                f"Patch the {s['undetected']} exploitable+undetected finding(s) and add detection rules."
            )
        if s["exploitable"]:
            priorities.append("Upgrade packages behind the exploitable findings to fixed versions.")
        priorities.append("Re-run the assessment after patching to confirm risk drops.")
        confidence = "critical" if s["undetected"] else ("high" if s["exploitable"] else "medium")

    return RunSummary(
        run_id=run_id,
        headline=headline[:300],
        overall_posture=posture[:1000],
        top_priorities=json.dumps(priorities[:5]),
        confidence=confidence,
        source="rule-based",
        generated_by="static",
    )
