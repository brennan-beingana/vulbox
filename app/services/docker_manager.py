import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class BuildFailedError(Exception):
    pass


# Default sandbox config used when a repo has no .vulbox.yml.
_DEFAULT_SANDBOX_CONFIG: Dict[str, Any] = {
    "network": "none",       # "none" | "bridge"
    "read_only": True,
    "tmpfs": ["/tmp:rw,size=64m"],
    "ports": [],             # e.g. ["8080:80"]
    "command": None,
    "env": {},
}


def _log_path(run_id: Optional[int], name: str) -> Optional[Path]:
    if run_id is None:
        return None
    p = settings.project_root / "data" / "runs" / str(run_id) / "logs" / f"{name}.log"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _persist(run_id: Optional[int], name: str, cmd: list, result: subprocess.CompletedProcess) -> None:
    path = _log_path(run_id, name)
    if path is None:
        return
    try:
        path.write_text(
            f"$ {' '.join(cmd)}\n"
            f"--- exit: {result.returncode} ---\n"
            f"--- stdout ---\n{result.stdout or ''}\n"
            f"--- stderr ---\n{result.stderr or ''}\n"
        )
    except Exception:
        logger.exception("Failed to persist subprocess log", extra={"run_id": run_id, "phase": name})


class DockerManager:
    @staticmethod
    def clone_repo(repo_url: str, run_id: Optional[int] = None) -> Path:
        """Clone repo_url into a temp directory and return the path."""
        if settings.dev_mode:
            logger.info("DockerManager dev mode: skipping clone")
            return Path(tempfile.mkdtemp())
        tmp = Path(tempfile.mkdtemp())
        cmd = ["git", "clone", "--depth", "1", repo_url, str(tmp)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        _persist(run_id, "clone", cmd, result)
        if result.returncode != 0:
            raise BuildFailedError(f"git clone failed: {result.stderr}")
        return tmp

    @staticmethod
    def build_image(repo_path: Path, tag: str, run_id: Optional[int] = None) -> str:
        """Build Docker image from repo_path, return the image tag."""
        if settings.dev_mode:
            logger.info("DockerManager dev mode: skipping docker build", extra={"tag": tag})
            return tag
        cmd = ["docker", "build", "-t", tag, str(repo_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        _persist(run_id, "build", cmd, result)
        if result.returncode != 0:
            raise BuildFailedError(f"docker build failed: {result.stderr}")
        logger.info("Image built", extra={"tag": tag})
        return tag

    @staticmethod
    def load_sandbox_config(repo_path: Optional[Path]) -> Dict[str, Any]:
        """Read sandbox.* keys from .vulbox.yml in repo_path, merged over defaults.

        Defaults stay locked-down (no network, read-only). The repo opts in to
        relaxations explicitly. Missing or malformed file → defaults.
        """
        cfg: Dict[str, Any] = dict(_DEFAULT_SANDBOX_CONFIG)
        if repo_path is None:
            return cfg
        cfg_path = repo_path / ".vulbox.yml"
        if not cfg_path.is_file():
            return cfg
        try:
            data = yaml.safe_load(cfg_path.read_text()) or {}
        except yaml.YAMLError as exc:
            logger.warning("Invalid .vulbox.yml; falling back to defaults", extra={"err": str(exc)})
            return cfg
        sandbox = (data.get("sandbox") or {}) if isinstance(data, dict) else {}
        for key in ("network", "read_only", "tmpfs", "ports", "command", "env"):
            if key in sandbox:
                cfg[key] = sandbox[key]
        return cfg

    @staticmethod
    def run_sandbox(
        image_tag: str,
        run_id: Optional[int] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Start container with the given sandbox config, return container_id."""
        if settings.dev_mode:
            logger.info("DockerManager dev mode: skipping sandbox launch")
            return "dev-container-id"

        cfg = config or dict(_DEFAULT_SANDBOX_CONFIG)
        cmd: list = ["docker", "run", "-d", "--label", f"vulbox.run_id={run_id}"]

        network = cfg.get("network", "none")
        cmd += ["--network", str(network)]

        if cfg.get("read_only", True):
            cmd.append("--read-only")

        for entry in cfg.get("tmpfs", []) or []:
            cmd += ["--tmpfs", str(entry)]

        for port in cfg.get("ports", []) or []:
            cmd += ["-p", str(port)]

        for k, v in (cfg.get("env") or {}).items():
            cmd += ["-e", f"{k}={v}"]

        cmd.append(image_tag)

        if cfg.get("command"):
            command_val = cfg["command"]
            if isinstance(command_val, list):
                cmd += [str(c) for c in command_val]
            else:
                cmd += [str(command_val)]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        _persist(run_id, "sandbox-start", cmd, result)
        if result.returncode != 0:
            raise RuntimeError(f"docker run failed: {result.stderr}")
        container_id = result.stdout.strip()
        logger.info(
            "Sandbox started",
            extra={"container_id": container_id, "run_id": run_id, "network": network},
        )
        return container_id

    @staticmethod
    def rebuild_and_restart(
        container_id: str,
        image_tag: str,
        run_id: Optional[int] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Stop old container, start fresh one (Self-Healing Pipeline)."""
        if settings.dev_mode:
            return "dev-container-id-rebuilt"
        DockerManager.destroy_sandbox(container_id)
        return DockerManager.run_sandbox(image_tag, run_id, config=config)

    @staticmethod
    def destroy_sandbox(container_id: str) -> None:
        """Stop and remove the sandbox container."""
        if settings.dev_mode or container_id in ("dev-container-id", "dev-container-id-rebuilt"):
            return
        subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=15)
        subprocess.run(["docker", "rm", container_id], capture_output=True, timeout=15)
        logger.info("Sandbox destroyed", extra={"container_id": container_id})
