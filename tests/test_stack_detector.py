"""Unit tests for StackDetector — Dockerfile + manifest fingerprinting."""
import os

os.environ["VULBOX_DEV_MODE"] = "true"

from app.services.stack_detector import StackDetector, TechProfile  # noqa: E402


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content)


def test_empty_repo_yields_empty_profile(tmp_path):
    profile = StackDetector.detect(tmp_path)
    assert isinstance(profile, TechProfile)
    assert profile.is_empty()
    assert profile.tags() == set()


def test_none_path_yields_empty_profile():
    assert StackDetector.detect(None).is_empty()


def test_dockerfile_from_detects_language_and_version(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM python:3.11-slim\nCMD [\"python\", \"app.py\"]\n")
    profile = StackDetector.detect(tmp_path)
    assert "python" in profile.tags()
    py = next(t for t in profile.techs if t.name == "python" and t.source == "dockerfile:FROM")
    assert py.version == "3.11"
    assert py.confidence == 1.0


def test_fastapi_from_dockerfile_and_requirements(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM python:3.12\nCMD [\"uvicorn\", \"main:app\"]\n")
    _write(tmp_path, "requirements.txt", "fastapi==0.110.0\nuvicorn[standard]>=0.27\npydantic\n")
    profile = StackDetector.detect(tmp_path)
    tags = profile.tags()
    assert {"python", "fastapi", "uvicorn"} <= tags
    fa = next(t for t in profile.techs if t.name == "fastapi")
    assert fa.version == "0.110.0"
    assert fa.confidence == 0.9


def test_django_detected_from_requirements(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM python:3.11\n")
    _write(tmp_path, "requirements.txt", "Django>=4.2,<5.0\ngunicorn\n")
    profile = StackDetector.detect(tmp_path)
    assert {"python", "django"} <= profile.tags()
    dj = next(t for t in profile.techs if t.name == "django")
    assert dj.version == "4.2"


def test_node_express_from_package_json(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM node:20-alpine\n")
    _write(
        tmp_path,
        "package.json",
        '{"dependencies": {"express": "^4.18.2", "lodash": "^4.17.21"}}',
    )
    profile = StackDetector.detect(tmp_path)
    assert {"node", "express"} <= profile.tags()
    ex = next(t for t in profile.techs if t.name == "express")
    assert ex.version == "4.18.2"


def test_java_spring_from_pom(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM eclipse-temurin:17-jre\n")
    _write(
        tmp_path,
        "pom.xml",
        "<project><dependencies><dependency>"
        "<groupId>org.springframework.boot</groupId>"
        "<artifactId>spring-boot-starter-web</artifactId>"
        "</dependency></dependencies></project>",
    )
    profile = StackDetector.detect(tmp_path)
    assert {"java", "java-spring"} <= profile.tags()


def test_malformed_package_json_still_yields_node(tmp_path):
    _write(tmp_path, "package.json", "{not valid json")
    profile = StackDetector.detect(tmp_path)
    # Presence of the manifest is itself signal; framework parse just no-ops.
    assert "node" in profile.tags()
    assert "express" not in profile.tags()


def test_go_and_ruby_manifests(tmp_path):
    _write(tmp_path, "go.mod", "module example.com/app\n\ngo 1.22\n")
    profile_go = StackDetector.detect(tmp_path)
    assert "go" in profile_go.tags()


def test_rails_from_gemfile(tmp_path):
    _write(tmp_path, "Gemfile", "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n")
    profile = StackDetector.detect(tmp_path)
    assert {"ruby", "rails"} <= profile.tags()


def test_comments_and_blank_lines_ignored_in_dockerfile(tmp_path):
    _write(
        tmp_path,
        "Dockerfile",
        "# build stage\n\nFROM python:3.10 AS build\n# comment\nRUN pip install flask\n",
    )
    _write(tmp_path, "requirements.txt", "# pinned deps\nflask==3.0.0\n")
    profile = StackDetector.detect(tmp_path)
    assert {"python", "flask"} <= profile.tags()


def test_multistage_dockerfile_picks_up_both_from_lines(tmp_path):
    _write(
        tmp_path,
        "Dockerfile",
        "FROM golang:1.22 AS build\nFROM node:20\n",
    )
    profile = StackDetector.detect(tmp_path)
    assert {"go", "node"} <= profile.tags()
