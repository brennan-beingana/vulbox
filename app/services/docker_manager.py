import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import unquote, urlsplit

import yaml

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class BuildFailedError(Exception):
    pass


class SandboxNotRunningError(RuntimeError):
    """Raised when the sandbox container is not in 'running' state.

    Common cause: the target image's entrypoint exited immediately because
    --network none / --read-only / no port broke its startup. Without this
    check, the orchestrator runs ART tests against a corpse and reports
    nonsense results.
    """


# Default sandbox config used when a repo has no .vulbox.yml. `read_only` is
# resolved from settings at call time (see _default_sandbox_config) so the
# global posture is env-controllable; the rest stay locked down (no network).
def _default_sandbox_config() -> Dict[str, Any]:
    return {
        "network": "none",       # "none" | "bridge"
        "read_only": settings.sandbox_default_read_only,
        "tmpfs": ["/tmp:rw,size=64m"],
        "ports": [],             # e.g. ["8080:80"]
        "command": None,
        "env": {},
    }


def _as_local_path(repo_url: str) -> Optional[Path]:
    """Return a filesystem path if repo_url already points at a local checkout.

    Handles ``file://`` URLs and bare absolute/relative/``~`` paths. These need
    no network, so we reference them directly instead of cloning (used by the
    e2e/vulhub harnesses, which materialize each target as a local repo).
    """
    s = repo_url.strip()
    if s.startswith("file://"):
        return Path(s[len("file://"):])
    if s.startswith(("/", "./", "../", "~")):
        return Path(s).expanduser()
    return None


def _repo_slug(repo_url: str) -> str:
    """Stable, filesystem-safe directory name for a remote repo URL.

    Keeps the host/org/repo shape so two repos with the same trailing name don't
    collide (e.g. ``github.com__org__repo``). Same URL → same slug → same cache.
    """
    s = repo_url.strip().rstrip("/")
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)  # drop scheme
    s = re.sub(r"^[^@/]+@", "", s)                       # drop user@ (scp-style ssh)
    s = s.replace(":", "/")                              # git@host:org/repo
    if s.endswith(".git"):
        s = s[:-4]
    s = re.sub(r"[^A-Za-z0-9._/-]", "_", s)
    s = s.replace("/", "__").strip("_")
    return s or "repo"


@dataclass
class ParsedRepo:
    """A remote repo URL decomposed into what we clone vs. what we build.

    ``clone_url`` is the repository to ``git clone``; ``ref`` is the branch/tag
    to check out (None = remote default); ``subpath`` is the directory *within*
    the repo whose Dockerfile is the build context ("" = repo root).
    """
    clone_url: str
    ref: Optional[str]
    subpath: str


def _parse_repo_url(repo_url: str) -> ParsedRepo:
    """Split a repo URL, understanding GitHub/GitLab ``tree``/``blob`` subpaths.

    A presentation URL pasted straight from the browser —
    ``https://github.com/vulhub/vulhub/tree/master/node/CVE-2017-14849`` — is
    decomposed into the repo to clone (``…/vulhub/vulhub.git``), the ref
    (``master``), and the subdir to build (``node/CVE-2017-14849``). GitLab's
    ``/-/tree/`` form is handled too. Anything without a ``tree``/``blob``
    marker is treated as a plain repo URL (clone root, default branch).

    Caveat: the segment right after ``tree``/``blob`` is taken as the ref, so a
    branch name containing ``/`` can't be distinguished from the subpath — fine
    for the usual ``master``/``main``/tag refs.
    """
    s = repo_url.strip()
    parts = urlsplit(s)
    if parts.scheme in ("http", "https") and parts.netloc:
        segs = [seg for seg in parts.path.split("/") if seg]
        for marker in ("tree", "blob"):
            if marker not in segs:
                continue
            i = segs.index(marker)
            repo_segs = segs[:i]
            if repo_segs and repo_segs[-1] == "-":  # GitLab /org/repo/-/tree/...
                repo_segs = repo_segs[:-1]
            if len(repo_segs) >= 2 and len(segs) > i + 1:
                ref = unquote(segs[i + 1])
                raw_subpath = [unquote(x) for x in segs[i + 2:]]
                # Reject path traversal — the build context must stay in-repo.
                if any(seg in ("..", "") for seg in raw_subpath):
                    raise BuildFailedError(f"invalid subpath in repo_url: {s}")
                clone_url = f"{parts.scheme}://{parts.netloc}/{'/'.join(repo_segs)}.git"
                return ParsedRepo(clone_url=clone_url, ref=ref, subpath="/".join(raw_subpath))
    return ParsedRepo(clone_url=s, ref=None, subpath="")


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
        """Resolve repo_url to a local build dir, cloning remote repos once.

        Understands browser ``tree``/``blob`` URLs pointing at a **subdirectory**
        of a repo (e.g. a single vulhub app): the whole repo is cloned in the
        background into a persistent cache at ``settings.local_repos_dir/<slug>``
        and the returned path is the requested subdir — which is then what the
        pipeline builds, stack-detects, and reads ``.vulbox.yml`` from.

        The clone is cached and reused on later runs: if the checkout already
        exists we try to update it, but a failed update (the recurring transient
        pull failure) degrades to the cached copy rather than failing the build.
        Only a first-ever clone of a repo we have no cache for can raise.
        Local/``file://`` URLs are referenced in place.
        """
        if settings.dev_mode:
            logger.info("DockerManager dev mode: skipping clone")
            return Path(tempfile.mkdtemp())

        local = _as_local_path(repo_url)
        if local is not None:
            if not local.is_dir():
                raise BuildFailedError(f"local repo path not found: {local}")
            logger.info("Using local repo path directly", extra={"path": str(local)})
            return local

        parsed = _parse_repo_url(repo_url)
        base = settings.local_repos_dir
        base.mkdir(parents=True, exist_ok=True)
        dest = base / _repo_slug(parsed.clone_url)

        if (dest / ".git").is_dir():
            if DockerManager._update_repo(dest, parsed.ref, run_id):
                logger.info("Reused cached repo (updated)", extra={"path": str(dest)})
            else:
                logger.warning(
                    "Cached repo update failed; building from cached checkout",
                    extra={"path": str(dest), "repo_url": repo_url},
                )
        else:
            # No cache yet (or a stale/partial dir without .git): clone fresh.
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            cmd = ["git", "clone", "--depth", "1"]
            if parsed.ref:
                cmd += ["--branch", parsed.ref]
            cmd += [parsed.clone_url, str(dest)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            _persist(run_id, "clone", cmd, result)
            if result.returncode != 0:
                shutil.rmtree(dest, ignore_errors=True)  # don't leave a partial cache
                raise BuildFailedError(f"git clone failed: {result.stderr}")
            logger.info("Cloned repo into cache", extra={"path": str(dest)})

        build_dir = dest / parsed.subpath if parsed.subpath else dest
        if not build_dir.is_dir():
            raise BuildFailedError(
                f"subdirectory '{parsed.subpath}' not found in {parsed.clone_url} "
                f"(checked {build_dir})"
            )
        if parsed.subpath:
            logger.info(
                "Building from repo subdir",
                extra={"clone_url": parsed.clone_url, "subpath": parsed.subpath},
            )
        return build_dir

    @staticmethod
    def _update_repo(dest: Path, ref: Optional[str] = None, run_id: Optional[int] = None) -> bool:
        """Best-effort refresh of a cached checkout to the remote tip.

        Shallow fetch of ``ref`` (or the remote default) + hard reset to
        FETCH_HEAD. Returns False on any error so the caller can fall back to the
        existing checkout instead of failing.
        """
        fetch = ["git", "fetch", "--depth", "1", "origin"] + ([ref] if ref else [])
        r1 = subprocess.run(fetch, cwd=dest, capture_output=True, text=True, timeout=120)
        _persist(run_id, "clone-fetch", fetch, r1)
        if r1.returncode != 0:
            return False
        reset = ["git", "reset", "--hard", "FETCH_HEAD"]
        r2 = subprocess.run(reset, cwd=dest, capture_output=True, text=True, timeout=60)
        _persist(run_id, "clone-reset", reset, r2)
        return r2.returncode == 0

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

        Network stays locked down (none) by default; read-only follows the
        global VULBOX_SANDBOX_READ_ONLY posture. The repo opts in to relaxations
        explicitly. Missing or malformed file → defaults.
        """
        cfg: Dict[str, Any] = _default_sandbox_config()
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

        cfg = config or _default_sandbox_config()
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
    def assert_running(container_id: str, settle_secs: float = 1.5) -> None:
        """Verify the sandbox is still 'running' after a brief settle.

        Brief sleep gives the container time to either fully boot or crash;
        without it, an immediate-exit image looks running for milliseconds.
        Raises SandboxNotRunningError with the docker-side state and the
        first 40 lines of container logs if it isn't.
        """
        if settings.dev_mode:
            return
        import time
        time.sleep(settle_secs)

        inspect = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}|{{.State.ExitCode}}|{{.State.Error}}", container_id],
            capture_output=True, text=True, timeout=10,
        )
        if inspect.returncode != 0:
            raise SandboxNotRunningError(
                f"docker inspect failed for {container_id}: {inspect.stderr.strip()}"
            )
        status, exit_code, err = (inspect.stdout.strip().split("|", 2) + ["", "", ""])[:3]
        if status != "running":
            tail = subprocess.run(
                ["docker", "logs", "--tail", "40", container_id],
                capture_output=True, text=True, timeout=10,
            )
            log_excerpt = (tail.stdout or "") + (tail.stderr or "")
            raise SandboxNotRunningError(
                f"sandbox {container_id[:12]} not running "
                f"(state={status}, exit={exit_code}, err={err!r}). "
                f"Last container output:\n{log_excerpt[:1500]}"
            )

    @staticmethod
    def destroy_sandbox(container_id: str) -> None:
        """Stop and remove the sandbox container."""
        if settings.dev_mode or container_id in ("dev-container-id", "dev-container-id-rebuilt"):
            return
        subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=15)
        subprocess.run(["docker", "rm", container_id], capture_output=True, timeout=15)
        logger.info("Sandbox destroyed", extra={"container_id": container_id})
