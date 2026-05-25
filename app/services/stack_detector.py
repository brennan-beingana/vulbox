"""Detect a target repo's technology stack from its Dockerfile + manifests.

Runs once, early in the pipeline, against the cloned repo path. The result
(a TechProfile) lets the ART queue proactively select framework-relevant
attacks instead of only reacting to Trivy findings.

Best-effort by design: anything unparseable is skipped, and a repo with no
recognizable Dockerfile/manifest yields an empty profile. Detection must
never fail the run, so detect() swallows its own errors.
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

from app.core.logging import get_logger

logger = get_logger(__name__)

# Cap how much of any single file we read — manifests are small; this guards
# against a pathological/binary file masquerading as one.
_MAX_FILE_BYTES = 256 * 1024

# Confidence tiers.
_CONF_BASE_IMAGE = 1.0   # Dockerfile FROM — authoritative
_CONF_MANIFEST = 0.9     # declared dependency
_CONF_KEYWORD = 0.6      # CMD/ENTRYPOINT/RUN keyword guess

# Dockerfile `FROM <image>` → canonical language tag. Substring match on the
# image name (before any tag/digest), longest key first so e.g. "python" beats
# a hypothetical shorter alias.
_BASE_IMAGE_LANG = {
    "python": "python",
    "node": "node",
    "openjdk": "java",
    "eclipse-temurin": "java",
    "amazoncorretto": "java",
    "golang": "go",
    "ruby": "ruby",
    "php": "php",
}

# CMD/ENTRYPOINT/RUN tokens → (tag, also-implies-language|None).
_RUNTIME_KEYWORDS = {
    "uvicorn": ("uvicorn", "python"),
    "gunicorn": ("gunicorn", "python"),
    "hypercorn": ("hypercorn", "python"),
    "node": ("node", "node"),
}

# Manifest dependency name → framework tag. Checked as a whole-word match
# against the manifest's declared dependency names.
_PY_FRAMEWORKS = {
    "fastapi": "fastapi",
    "django": "django",
    "flask": "flask",
    "starlette": "starlette",
    "tornado": "tornado",
}
_NODE_FRAMEWORKS = {
    "express": "express",
    "next": "next",
    "koa": "koa",
    "@nestjs/core": "nestjs",
    "fastify": "fastify",
}


@dataclass
class DetectedTech:
    name: str               # canonical tag, e.g. "python", "fastapi", "java"
    version: Optional[str]  # best-effort; None when not recoverable
    source: str             # provenance, e.g. "dockerfile:FROM", "manifest:requirements.txt"
    confidence: float


@dataclass
class TechProfile:
    techs: List[DetectedTech] = field(default_factory=list)

    def tags(self) -> Set[str]:
        """Flat set of detected tags for matching against attack profiles."""
        return {t.name for t in self.techs}

    def is_empty(self) -> bool:
        return not self.techs

    def add(self, tech: DetectedTech) -> None:
        """Add a tech, keeping the highest-confidence entry per (name, source)."""
        for existing in self.techs:
            if existing.name == tech.name and existing.source == tech.source:
                if tech.confidence > existing.confidence or (
                    existing.version is None and tech.version is not None
                ):
                    existing.version = tech.version or existing.version
                    existing.confidence = max(existing.confidence, tech.confidence)
                return
        self.techs.append(tech)


def _read_text(path: Path) -> Optional[str]:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _parse_dockerfile(text: str, profile: TechProfile) -> None:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()

        if upper.startswith("FROM "):
            # FROM python:3.11-slim AS build  →  image="python:3.11-slim"
            parts = line.split()
            image = parts[1] if len(parts) > 1 else ""
            name_and_tag = image.split("@")[0]  # drop digest
            name = name_and_tag.split(":")[0].split("/")[-1].lower()
            tag = name_and_tag.split(":")[1] if ":" in name_and_tag else None
            for key, lang in sorted(_BASE_IMAGE_LANG.items(), key=lambda x: -len(x[0])):
                if key in name:
                    version = None
                    if tag:
                        m = re.match(r"(\d+(?:\.\d+)*)", tag)
                        version = m.group(1) if m else None
                    profile.add(DetectedTech(lang, version, "dockerfile:FROM", _CONF_BASE_IMAGE))
                    break

        elif upper.startswith("CMD ") or upper.startswith("ENTRYPOINT ") or upper.startswith("RUN "):
            lowered = line.lower()
            for token, (tag, implies) in _RUNTIME_KEYWORDS.items():
                if re.search(rf"\b{re.escape(token)}\b", lowered):
                    profile.add(DetectedTech(tag, None, "dockerfile:CMD", _CONF_KEYWORD))
                    if implies:
                        profile.add(DetectedTech(implies, None, "dockerfile:CMD", _CONF_KEYWORD))


def _parse_requirements(text: str, profile: TechProfile, source: str) -> None:
    """requirements.txt / Pipfile / pyproject — scan lines for known frameworks."""
    profile.add(DetectedTech("python", None, source, _CONF_MANIFEST))
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        # Split off version specifier: fastapi==0.110.0, django>=4.2, "flask"
        name = re.split(r"[<>=!~\[\s;\"']", line, maxsplit=1)[0].strip()
        if name in _PY_FRAMEWORKS:
            m = re.search(rf"{re.escape(name)}\s*[=>~]+\s*v?(\d+(?:\.\d+)*)", line)
            version = m.group(1) if m else None
            profile.add(DetectedTech(_PY_FRAMEWORKS[name], version, source, _CONF_MANIFEST))


def _parse_package_json(text: str, profile: TechProfile) -> None:
    profile.add(DetectedTech("node", None, "manifest:package.json", _CONF_MANIFEST))
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return
    if not isinstance(data, dict):
        return
    deps = {}
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.update(section)
    for dep, raw_ver in deps.items():
        tag = _NODE_FRAMEWORKS.get(dep.lower())
        if tag:
            version = None
            if isinstance(raw_ver, str):
                m = re.search(r"(\d+(?:\.\d+)*)", raw_ver)
                version = m.group(1) if m else None
            profile.add(DetectedTech(tag, version, "manifest:package.json", _CONF_MANIFEST))


def _parse_pom(text: str, profile: TechProfile) -> None:
    profile.add(DetectedTech("java", None, "manifest:pom.xml", _CONF_MANIFEST))
    if "spring-boot" in text.lower() or "springframework" in text.lower():
        profile.add(DetectedTech("java-spring", None, "manifest:pom.xml", _CONF_MANIFEST))


def _parse_gradle(text: str, profile: TechProfile) -> None:
    profile.add(DetectedTech("java", None, "manifest:build.gradle", _CONF_MANIFEST))
    if "spring-boot" in text.lower() or "springframework" in text.lower():
        profile.add(DetectedTech("java-spring", None, "manifest:build.gradle", _CONF_MANIFEST))


def _parse_go_mod(text: str, profile: TechProfile) -> None:
    profile.add(DetectedTech("go", None, "manifest:go.mod", _CONF_MANIFEST))


def _parse_gemfile(text: str, profile: TechProfile) -> None:
    profile.add(DetectedTech("ruby", None, "manifest:Gemfile", _CONF_MANIFEST))
    if re.search(r"\brails\b", text.lower()):
        profile.add(DetectedTech("rails", None, "manifest:Gemfile", _CONF_MANIFEST))


# Manifest filename → parser. pyproject/Pipfile reuse the requirements scanner
# (a substring scan for framework names works across all three formats).
_MANIFEST_PARSERS = {
    "requirements.txt": lambda t, p: _parse_requirements(t, p, "manifest:requirements.txt"),
    "pyproject.toml": lambda t, p: _parse_requirements(t, p, "manifest:pyproject.toml"),
    "Pipfile": lambda t, p: _parse_requirements(t, p, "manifest:Pipfile"),
    "package.json": _parse_package_json,
    "pom.xml": _parse_pom,
    "build.gradle": _parse_gradle,
    "go.mod": _parse_go_mod,
    "Gemfile": _parse_gemfile,
}


class StackDetector:
    @staticmethod
    def detect(repo_path: Optional[Path]) -> TechProfile:
        """Fingerprint the technology stack of the repo at repo_path.

        Never raises — on any failure it logs and returns whatever was gathered
        so far (possibly an empty profile). An empty profile is a valid result:
        the ART queue degrades to its existing reactive behavior.
        """
        profile = TechProfile()
        if repo_path is None:
            return profile
        try:
            dockerfile = _read_text(repo_path / "Dockerfile")
            if dockerfile:
                _parse_dockerfile(dockerfile, profile)

            for filename, parser in _MANIFEST_PARSERS.items():
                text = _read_text(repo_path / filename)
                if text:
                    parser(text, profile)
        except Exception:  # noqa: BLE001 — detection is best-effort, never blocks the run
            logger.exception("Stack detection failed", extra={"repo_path": str(repo_path)})

        logger.info("Stack detected", extra={"tags": sorted(profile.tags())})
        return profile
