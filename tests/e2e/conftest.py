"""Conftest for the end-to-end pipeline test (Deliverable A of demo_revamp.md).

Wires up:
- A pre-flight check that auto-skips e2e tests when Docker/Trivy aren't usable,
  so a green `pytest tests/` on a stripped-down dev box doesn't silently turn
  into "we never ran the real thing."
- `target_path`: a session-scoped temp dir holding a `git init`-ed copy of
  `tests/e2e/fixtures/vulnerable_target/` — `DockerManager.clone_repo` shells
  out to `git clone --depth 1 <url>`, which needs a real git repo as source.
- `api_client`: an authenticated wrapper around FastAPI's TestClient. Resets
  the SQLite DB before each test so prior runs don't bleed in.
- `AuthedClient.collect_ws_events`: drains the WebSocket into a list with a
  hard timeout, so a failed pipeline assertion gets a readable event log in
  the failure message instead of "timed out after 600s."
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterator, List

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_BASE = Path(__file__).resolve().parent / "fixtures"
FIXTURE_DIR = FIXTURE_BASE / "vulnerable_target"  # default target (node/express)
DB_PATH = PROJECT_ROOT / "data" / "findings.db"


def _tool_available(*cmd: str) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def pytest_collection_modifyitems(config, items):
    """Skip e2e tests when their host requirements aren't met.

    Loud, specific skip messages — "Docker daemon not reachable" beats a
    10-minute timeout with no useful output.
    """
    docker_ok = _tool_available("docker", "info")
    trivy_ok = _tool_available("trivy", "--version")
    falco_ok = _tool_available("falco", "--version")

    skip_docker = pytest.mark.skip(reason="docker daemon not reachable (run `docker info` to debug)")
    skip_trivy = pytest.mark.skip(reason="trivy CLI not on PATH (https://aquasecurity.github.io/trivy/)")
    skip_falco = pytest.mark.skip(reason="falco not installed (kernel module access required)")

    for item in items:
        if "requires_docker" in item.keywords and not docker_ok:
            item.add_marker(skip_docker)
        if "requires_trivy" in item.keywords and not trivy_ok:
            item.add_marker(skip_trivy)
        if "requires_falco" in item.keywords and not falco_ok:
            item.add_marker(skip_falco)


def _git_init_repo(src_dir: Path, dest: Path) -> Path:
    """Copy a fixture dir into ``dest`` and turn it into a git repo.

    `DockerManager.clone_repo` runs `git clone --depth 1 <url>`, so each target
    has to be a real repository.
    """
    if not (src_dir / "Dockerfile").is_file():
        pytest.fail(f"fixture missing Dockerfile: {src_dir}")

    for item in src_dir.iterdir():
        if item.is_dir():
            shutil.copytree(item, dest / item.name)
        else:
            shutil.copy2(item, dest / item.name)

    # Hermetic git identity so CI runners with no global git config still work.
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "vulbox-e2e",
        "GIT_AUTHOR_EMAIL": "e2e@vulbox.local",
        "GIT_COMMITTER_NAME": "vulbox-e2e",
        "GIT_COMMITTER_EMAIL": "e2e@vulbox.local",
    }
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=dest, check=True, env=env)
    subprocess.run(["git", "add", "."], cwd=dest, check=True, env=env)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", f"{src_dir.name} fixture"],
        cwd=dest, check=True, env=env,
    )
    return dest


@pytest.fixture(scope="session")
def make_target_repo(tmp_path_factory):
    """Factory: fixture dir name → git-initialized repo path (cached per name).

    Lets the parametrized e2e suite spin up multiple stack targets while each
    repo is materialized at most once per session.
    """
    cache: dict = {}

    def _make(fixture_name: str) -> Path:
        if fixture_name in cache:
            return cache[fixture_name]
        src = FIXTURE_BASE / fixture_name
        repo = tmp_path_factory.mktemp(f"{fixture_name}_repo")
        cache[fixture_name] = _git_init_repo(src, repo)
        return cache[fixture_name]

    return _make


@pytest.fixture(scope="session")
def target_path(make_target_repo) -> Path:
    """Backward-compatible alias for the default node/express target repo."""
    return make_target_repo("vulnerable_target")


@pytest.fixture
def api_client(monkeypatch) -> Iterator["AuthedClient"]:
    """Boot the FastAPI app in production mode against a fresh SQLite file.

    Production mode here means TrivyAdapter, ARTAdapter, and DockerManager all
    call real binaries — that's the whole point of E2E. The DB is reset before
    each test so a prior FAILED run doesn't contaminate assertions.

    We delete the DB *before* importing `app.main`, because the module-level
    `engine`/`SessionLocal` in `app.core.database` and the captured
    `SessionLocal` in `app.services.orchestrator` are evaluated at import
    time. Pointing at the project's default `data/findings.db` keeps all of
    those bindings consistent without needing to monkeypatch each one.
    """
    monkeypatch.setenv("VULBOX_DEV_MODE", "false")
    monkeypatch.setenv(
        "VULBOX_FALCO_ENABLED", os.getenv("VULBOX_FALCO_ENABLED", "false")
    )

    if DB_PATH.exists():
        DB_PATH.unlink()

    from fastapi.testclient import TestClient

    from app.core import config as config_module
    from app.core.config import Settings
    config_module.settings = Settings()  # rebuild with VULBOX_DEV_MODE=false

    from app.main import app

    with TestClient(app) as client:
        yield AuthedClient(client)


class AuthedClient:
    """Thin wrapper that registers a user and remembers the bearer token.

    Kept deliberately minimal — TestClient does the heavy lifting; this just
    removes the per-test boilerplate of register/login/token plumbing.
    """

    def __init__(self, client) -> None:
        self.client = client
        self.token = self._register_and_login()
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def _register_and_login(self) -> str:
        email = f"e2e-{int(time.time() * 1000)}@vulbox.local"
        password = "e2e-password-1234"
        r = self.client.post("/auth/register", json={"email": email, "password": password})
        if r.status_code >= 400:
            pytest.fail(f"auth register failed: {r.status_code} {r.text}")
        r = self.client.post("/auth/login", json={"email": email, "password": password})
        if r.status_code >= 400:
            pytest.fail(f"auth login failed: {r.status_code} {r.text}")
        return r.json()["access_token"]

    def create_run(self, repo_url: str, project_name: str = "e2e-vulnerable-target") -> int:
        r = self.client.post(
            "/runs",
            json={
                "project_name": project_name,
                "repo_url": repo_url,
                "consent_granted": True,
            },
            headers=self.headers,
        )
        if r.status_code >= 400:
            pytest.fail(f"create_run failed: {r.status_code} {r.text}")
        return r.json()["id"]

    def get_run(self, run_id: int) -> dict:
        r = self.client.get(f"/runs/{run_id}", headers=self.headers)
        r.raise_for_status()
        return r.json()

    def get_report(self, run_id: int) -> dict:
        r = self.client.get(f"/reports/{run_id}", headers=self.headers)
        r.raise_for_status()
        return r.json()

    def poll_run(self, run_id: int, timeout: int = 900, interval: float = 2.0) -> dict:
        deadline = time.time() + timeout
        last: dict = {}
        while time.time() < deadline:
            last = self.get_run(run_id)
            if last["status"] in ("COMPLETE", "FAILED"):
                return last
            time.sleep(interval)
        pytest.fail(
            f"run {run_id} did not reach terminal status within {timeout}s; "
            f"last status: {last.get('status')!r}"
        )

    def collect_ws_events(self, run_id: int, max_seconds: int = 900) -> List[dict]:
        """Drain the run's WebSocket into a list, stopping at terminal event."""
        events: List[dict] = []
        deadline = time.time() + max_seconds
        with self.client.websocket_connect(f"/ws/runs/{run_id}/status") as ws:
            while time.time() < deadline:
                try:
                    msg = ws.receive_json()
                except Exception:
                    break
                events.append(msg)
                if msg.get("event") in ("complete", "failed", "error"):
                    break
        return events
