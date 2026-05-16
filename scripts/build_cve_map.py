#!/usr/bin/env python3
"""Build ``data/cve_technique_map.generated.yml`` from vendored source files.

Inputs (checked into ``data/sources/``):
    kev.json            CISA Known Exploited Vulnerabilities catalog.
    attack_to_cve.csv   Center for Threat-Informed Defense CVE→ATT&CK mappings.

Output:
    data/cve_technique_map.generated.yml

The generated file is loaded by :mod:`app.adapters.art_adapter` alongside the
hand-curated ``data/cve_technique_map.yml``. Curated entries take priority on
conflict, so the bulk auto-generated layer never overrides human judgement.

To refresh sources, re-download with::

    curl -sSL -o data/sources/kev.json \\
        https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    curl -sSL -o data/sources/attack_to_cve.csv \\
        'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv'

Then::

    python scripts/build_cve_map.py
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "data" / "sources"
KEV_PATH = SOURCES / "kev.json"
ATC_PATH = SOURCES / "attack_to_cve.csv"
CWE_PATH = ROOT / "data" / "cwe_technique_map.yml"
OUT_PATH = ROOT / "data" / "cve_technique_map.generated.yml"

_PROV_RANK = {"primary": 0, "secondary": 1, "exploitation": 2, "cwe_bridge": 3}


def load_cwe_bridge() -> Dict[str, List[str]]:
    """Return {CWE-XX: [technique, ...]} from the curated bridge file."""
    if not CWE_PATH.is_file():
        return {}
    data = yaml.safe_load(CWE_PATH.read_text()) or {}
    bridge: Dict[str, List[str]] = {}
    for entry in data.get("mappings", []) or []:
        cwe = (entry.get("cwe") or "").strip()
        tech = (entry.get("technique") or "").strip()
        if cwe and tech:
            bridge.setdefault(cwe, []).append(tech)
    return bridge


def load_kev() -> Dict[str, dict]:
    """Return {cve_id: kev_metadata} keyed for fast lookup."""
    data = json.loads(KEV_PATH.read_text())
    out: Dict[str, dict] = {}
    for v in data.get("vulnerabilities", []) or []:
        cve = (v.get("cveID") or "").strip()
        if not cve.startswith("CVE-"):
            continue
        out[cve] = {
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "cwes": v.get("cwes") or [],
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
        }
    return out


def _split_techniques(cell: str) -> List[str]:
    """Parse 'T1190; T1078, T1059' → ['T1190', 'T1078', 'T1059']."""
    if not cell:
        return []
    raw = cell.replace(",", ";")
    return [t.strip() for t in raw.split(";") if t.strip().startswith("T")]


def load_attack_to_cve() -> List[dict]:
    rows: List[dict] = []
    with ATC_PATH.open(newline="", encoding="utf-8-sig") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            cve = (row.get("CVE ID") or "").strip()
            if not cve.startswith("CVE-"):
                continue
            rows.append(
                {
                    "cve": cve,
                    "primary": _split_techniques(row.get("Primary Impact", "")),
                    "secondary": _split_techniques(row.get("Secondary Impact", "")),
                    "exploitation": _split_techniques(
                        row.get("Exploitation Technique", "")
                    ),
                }
            )
    return rows


def build_entries(
    atc_rows: List[dict],
    kev: Dict[str, dict],
    cwe_bridge: Dict[str, List[str]],
) -> List[dict]:
    """Emit one entry per unique (CVE, technique).

    Three sources fill the map, in priority order:

    1. ``attack_to_cve`` — direct curated mappings (primary > secondary >
       exploitation). Most semantically-direct; consumed first.
    2. KEV ∩ CWE bridge — KEV CVEs whose CWEs we've mapped to a technique
       provide bulk coverage on actively-exploited vulnerabilities.
    3. KEV ∖ (attack_to_cve ∪ cwe_bridge) — annotated as ``kev:unmapped`` for
       visibility; the adapter still has no technique to test on these, but
       the dashboard can surface the residual gap.

    Within a CVE, ordering is primary < secondary < exploitation < cwe_bridge
    so the adapter (which keeps the first technique it sees per CVE) picks
    the most direct mapping.
    """
    seen: set = set()
    entries: List[dict] = []

    def annotate_kev(entry: dict, cve: str) -> None:
        meta = kev.get(cve)
        if meta is None:
            return
        entry["kev"] = True
        if meta["ransomware"]:
            entry["ransomware"] = True
        if meta["vendor"]:
            entry["vendor"] = meta["vendor"]

    def add(cve: str, tech: str, provenance: str) -> None:
        key = (cve, tech)
        if key in seen:
            return
        seen.add(key)
        entry: dict = {"cve": cve, "technique": tech, "provenance": provenance}
        annotate_kev(entry, cve)
        entries.append(entry)

    # 1. attack_to_cve direct mappings.
    for row in atc_rows:
        for t in row["primary"]:
            add(row["cve"], t, "attack_to_cve:primary")
        for t in row["secondary"]:
            add(row["cve"], t, "attack_to_cve:secondary")
        for t in row["exploitation"]:
            add(row["cve"], t, "attack_to_cve:exploitation")

    # 2. KEV via CWE bridge — only fills CVEs not already covered above.
    atc_cves: set = {row["cve"] for row in atc_rows}
    for cve, meta in kev.items():
        if cve in atc_cves:
            continue
        cwes = meta.get("cwes") or []
        bridged = False
        for cwe in cwes:
            for tech in cwe_bridge.get(cwe, []):
                add(cve, tech, f"kev:cwe_bridge:{cwe}")
                bridged = True
        if not bridged:
            # No technique resolvable, but worth recording so the dashboard
            # can show the residual gap. The adapter skips entries with no
            # technique, so this is informational only.
            entry = {
                "cve": cve,
                "technique": None,
                "provenance": "kev:unmapped",
            }
            annotate_kev(entry, cve)
            entries.append(entry)

    entries.sort(
        key=lambda e: (
            e["cve"],
            _PROV_RANK.get(
                (e["provenance"].split(":")[-1] if e["provenance"] else ""), 99
            ),
        )
    )
    return entries


def write_yaml(entries: List[dict], stats: dict) -> None:
    header = (
        "# AUTO-GENERATED by scripts/build_cve_map.py — do not edit by hand.\n"
        "# Sources: data/sources/kev.json, data/sources/attack_to_cve.csv\n"
        "# Curated overrides live in data/cve_technique_map.yml and win on conflict.\n"
        "#\n"
    )
    payload = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sources": {
                "kev": {
                    "path": "data/sources/kev.json",
                    "count": stats["kev_total"],
                },
                "attack_to_cve": {
                    "path": "data/sources/attack_to_cve.csv",
                    "count": stats["atc_total"],
                },
            },
            "stats": {
                "total_entries": len(entries),
                "unique_cves": stats["unique_cves"],
                "entries_on_kev": stats["entries_on_kev"],
                "unique_techniques": stats["unique_techniques"],
                "kev_bridged": stats["kev_bridged"],
                "kev_unmapped": stats["kev_unmapped"],
            },
        },
        "mappings": entries,
    }
    body = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)
    OUT_PATH.write_text(header + body)


def main() -> int:
    missing = [p for p in (KEV_PATH, ATC_PATH) if not p.is_file()]
    if missing:
        for p in missing:
            print(f"missing source: {p}", file=sys.stderr)
        print(
            "Refresh data/sources/ (see module docstring) and re-run.",
            file=sys.stderr,
        )
        return 1

    kev = load_kev()
    atc = load_attack_to_cve()
    cwe_bridge = load_cwe_bridge()
    entries = build_entries(atc, kev, cwe_bridge)

    actionable = [e for e in entries if e["technique"]]
    unmapped = [e for e in entries if not e["technique"]]

    stats = {
        "kev_total": len(kev),
        "atc_total": len(atc),
        "cwe_bridge_size": len(cwe_bridge),
        "unique_cves": len({e["cve"] for e in actionable}),
        "entries_on_kev": sum(1 for e in actionable if e.get("kev")),
        "unique_techniques": len({e["technique"] for e in actionable}),
        "kev_unmapped": len(unmapped),
        "kev_bridged": sum(
            1 for e in actionable if e["provenance"].startswith("kev:cwe_bridge")
        ),
    }

    write_yaml(entries, stats)

    print(
        f"Wrote {len(entries)} entries → {OUT_PATH.relative_to(ROOT)}\n"
        f"  unique CVEs:           {stats['unique_cves']}\n"
        f"  unique techniques:     {stats['unique_techniques']}\n"
        f"  entries on KEV:        {stats['entries_on_kev']}\n"
        f"  via CWE bridge:        {stats['kev_bridged']}\n"
        f"  KEV residual unmapped: {stats['kev_unmapped']}\n"
        f"  KEV catalog total:     {stats['kev_total']}\n"
        f"  attack_to_cve rows:    {stats['atc_total']}\n"
        f"  CWE bridge entries:    {stats['cwe_bridge_size']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
