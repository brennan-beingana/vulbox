"""Load the technology → attack profile catalog and resolve techniques per stack.

Pairs with StackDetector: given the detected tag set, returns the prioritized,
deduped list of MITRE techniques to proactively queue. The catalog lives at
data/tech_attack_profiles.yml. See that file's header for the schema and the
executability invariant enforced by tests/test_tech_profiles.py.
"""
from pathlib import Path
from typing import Dict, Iterable, List

import yaml

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_PROFILES_PATH = settings.project_root / "data" / "tech_attack_profiles.yml"


def _technique_ids(techniques: Iterable) -> List[str]:
    """Normalize a profile's `techniques` list to plain technique-id strings.

    Each item may be a bare id ("T1190") or a mapping ({id: T1190, reason: ...}).
    """
    ids: List[str] = []
    for item in techniques or []:
        if isinstance(item, str):
            tid = item
        elif isinstance(item, dict):
            tid = item.get("id")
        else:
            tid = None
        if tid:
            ids.append(tid)
    return ids


def load_tech_profiles() -> Dict[str, List[str]]:
    """Return {tag: ordered technique ids}. Missing/malformed file → {}.

    Insertion order of the YAML `profiles` mapping is preserved (Python dicts
    are ordered), which is what gives techniques_for() its file-controlled
    priority.
    """
    if not _PROFILES_PATH.is_file():
        logger.warning("Tech attack profiles file missing", extra={"path": str(_PROFILES_PATH)})
        return {}
    try:
        data = yaml.safe_load(_PROFILES_PATH.read_text()) or {}
    except yaml.YAMLError as exc:
        logger.warning("Invalid tech attack profiles", extra={"err": str(exc)})
        return {}
    profiles = data.get("profiles", {}) if isinstance(data, dict) else {}
    out: Dict[str, List[str]] = {}
    for tag, body in profiles.items():
        techniques = (body or {}).get("techniques") if isinstance(body, dict) else None
        out[tag] = _technique_ids(techniques)
    return out


def techniques_for(tags: Iterable[str]) -> List[str]:
    """Aggregate techniques for all profiles matching `tags`, deduped, in order.

    Profiles are visited in catalog (file) order so base-language techniques
    precede the framework techniques layered on top, and the first occurrence
    of a technique fixes its position.
    """
    tag_set = set(tags)
    profiles = load_tech_profiles()
    seen: set = set()
    ordered: List[str] = []
    for tag, technique_ids in profiles.items():
        if tag not in tag_set:
            continue
        for tid in technique_ids:
            if tid not in seen:
                seen.add(tid)
                ordered.append(tid)
    return ordered
