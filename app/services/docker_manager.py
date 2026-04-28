import subprocess
import tempfile
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class BuildFailedError(Exception):
    pass


class DockerManager:
    @staticmethod
    def clone_repo(repo_url: str) -> Path:
        """Clone repo_url into a temp directory and return the path."""
        if settings.dev_mode:
            logger.info("DockerManager dev mode: skipping clone")
            return Path(tempfile.mkdtemp())
        tmp = Path(tempfile.mkdtemp())
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(tmp)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise BuildFailedError(f"git clone failed: {result.stderr}")
        return tmp

    @staticmethod
    def build_image(repo_path: Path, tag: str) -> str:
        """Build Docker image from repo_path, return the image tag."""
        if settings.dev_mode:
            logger.info("DockerManager dev mode: skipping docker build", extra={"tag": tag})
            return tag
        result = subprocess.run(
            ["docker", "build", "-t", tag, str(repo_path)],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            raise BuildFailedError(f"docker build failed: {result.stderr}")
        logger.info("Image built", extra={"tag": tag})
        return tag

    @staticmethod
    def run_sandbox(image_tag: str) -> str:
        """
        Start container in an isolated network (no outbound), return container_id.
        Uses --network none for hard isolation.
        """
        if settings.dev_mode:
            logger.info("DockerManager dev mode: skipping sandbox launch")
            return "dev-container-id"
        result = subprocess.run(
            ["docker", "run", "-d", "--network", "none", "--read-only", image_tag],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker run failed: {result.stderr}")
        container_id = result.stdout.strip()
        logger.info("Sandbox started", extra={"container_id": container_id})
        return container_id

    @staticmethod
    def rebuild_and_restart(container_id: str, image_tag: str) -> str:
        """Stop old container, start fresh one (Self-Healing Pipeline)."""
        if settings.dev_mode:
            return "dev-container-id-rebuilt"
        DockerManager.destroy_sandbox(container_id)
        return DockerManager.run_sandbox(image_tag)

    @staticmethod
    def destroy_sandbox(container_id: str) -> None:
        """Stop and remove the sandbox container."""
        if settings.dev_mode or container_id in ("dev-container-id", "dev-container-id-rebuilt"):
            return
        subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=15)
        subprocess.run(["docker", "rm", container_id], capture_output=True, timeout=15)
        logger.info("Sandbox destroyed", extra={"container_id": container_id})
