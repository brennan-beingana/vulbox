#!/usr/bin/env bash
# Adversarial test runner — executes a single MITRE technique inside the
# sandbox container via `docker exec`. Designed to produce real syscalls
# Falco can observe.
#
# Exit conventions (consumed by ARTAdapter._run_atomic):
#   0  technique succeeded — image was exploitable
#   1  technique failed    — image resisted (or not applicable)
#   2  crash               — orchestrator should rebuild
#
# Required env:
#   VULBOX_SANDBOX_CONTAINER  container id/name to exec into
#   ATOMIC_CONSENT=true       FR-01 consent gate
#
# Usage: atomic_runner.sh <MITRE_TECHNIQUE_ID>

set -uo pipefail

if [[ "${ATOMIC_CONSENT:-false}" != "true" ]]; then
  echo "Atomic validation blocked: set ATOMIC_CONSENT=true to proceed."
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <technique_id>"
  exit 1
fi

TEST_ID="$1"
CONTAINER="${VULBOX_SANDBOX_CONTAINER:-}"

if [[ -z "$CONTAINER" ]]; then
  echo "VULBOX_SANDBOX_CONTAINER not set; cannot exec. Treating as non-exploitable."
  exit 1
fi

# Sanity: container must be running. If it's already gone, that's a crash.
state=$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "missing")
if [[ "$state" != "running" ]]; then
  echo "Sandbox container state=$state — crash."
  exit 2
fi

# Helper: run a command inside the sandbox and report.
exec_in() {
  local desc="$1"; shift
  echo ">>> [$TEST_ID] $desc"
  echo ">>> docker exec $CONTAINER $*"
  if docker exec "$CONTAINER" "$@" 2>&1; then
    echo ">>> RESULT: success"
    return 0
  else
    echo ">>> RESULT: failure (rc=$?)"
    return 1
  fi
}

case "$TEST_ID" in
  T1059|T1059.004)
    # Unix Shell command execution — the most basic foothold. Succeeds on any
    # image that ships /bin/sh, fails on distroless / scratch / FROM-only images.
    exec_in "Unix shell exec" /bin/sh -c 'id; uname -a; ls /etc | head'
    rc=$?
    ;;

  T1068)
    # Privilege escalation via pkexec (Polkit, CVE-2021-4034). Only succeeds on
    # images that include a vulnerable polkit; minimal images don't.
    exec_in "pkexec presence" /bin/sh -c 'command -v pkexec >/dev/null && pkexec --version'
    rc=$?
    ;;

  T1611)
    # Container escape probe — attempt to read host filesystem via /proc/1/root.
    # In a properly isolated rootless container this returns EACCES; if the
    # container runs as root with --privileged or with /proc not masked, it
    # leaks the host /etc/shadow.
    exec_in "Read host /etc/shadow via /proc/1/root" \
      /bin/sh -c 'cat /proc/1/root/etc/shadow 2>/dev/null | head -1'
    rc=$?
    ;;

  T1543.002)
    # Persistence via systemd unit file. Fails if the FS is read-only or if
    # /etc/systemd doesn't exist. Succeeds on images that ship systemd writable.
    exec_in "Write systemd unit" \
      /bin/sh -c 'mkdir -p /etc/systemd/system && \
                  printf "[Service]\nExecStart=/bin/false\n" > /etc/systemd/system/vulbox-atomic.service'
    rc=$?
    ;;

  T1190)
    # Exploit public-facing app — naive HTTP request to localhost. With
    # --network none this always fails (proves isolation). With network
    # access, returns whatever the app serves.
    exec_in "Localhost HTTP probe" \
      /bin/sh -c '(command -v wget >/dev/null && wget -qO- --timeout 3 http://127.0.0.1/ | head -1) || \
                   (command -v curl >/dev/null && curl -fsS --max-time 3 http://127.0.0.1/ | head -1) || \
                   exit 1'
    rc=$?
    ;;

  T1082)
    # System Information Discovery — basic enumeration. Always succeeds on
    # any image with /bin/sh; the value is in *what* the enumeration reveals
    # (kernel version, distro, package manager presence) downstream.
    exec_in "System info enumeration" \
      /bin/sh -c 'uname -a; cat /etc/os-release 2>/dev/null | head -5; \
                  command -v apt >/dev/null && echo HAS_APT; \
                  command -v apk >/dev/null && echo HAS_APK; \
                  command -v yum >/dev/null && echo HAS_YUM; \
                  ls /proc/1/cgroup 2>/dev/null | head -1'
    rc=$?
    ;;

  T1552.001)
    # Credentials in Files — sweep for plaintext secrets in standard locations.
    # Succeeds if any well-known credential file is readable.
    exec_in "Credential file sweep" \
      /bin/sh -c 'found=0; \
                  for p in /etc/shadow /etc/passwd /root/.bash_history \
                           /root/.ssh/id_rsa /etc/mysql/debian.cnf \
                           /var/www/.env /app/.env; do \
                    if [ -r "$p" ] && [ -s "$p" ]; then \
                      echo "READABLE: $p"; found=1; \
                    fi; \
                  done; \
                  [ $found -eq 1 ]'
    rc=$?
    ;;

  T1003)
    # OS Credential Dumping — read /etc/shadow. Succeeds when the container
    # runs as root with no FS hardening (the whole point of the test).
    exec_in "Read /etc/shadow" \
      /bin/sh -c 'cat /etc/shadow 2>/dev/null | head -3 | grep -v "^$"'
    rc=$?
    ;;

  T1210)
    # Exploitation of Remote Services — probe localhost SMB/RDP ports. Largely
    # negative on app containers (which is the correct outcome) but documents
    # whether anything dangerous is listening.
    exec_in "Lateral-movement port probe" \
      /bin/sh -c '(command -v nc >/dev/null && (nc -z -w2 127.0.0.1 445 || nc -z -w2 127.0.0.1 3389)) || \
                   (command -v ss >/dev/null && ss -ltn 2>/dev/null | grep -E ":(445|3389) ") || \
                   exit 1'
    rc=$?
    ;;

  T1574)
    # Hijack Execution Flow — write a fake library to a path that ld would
    # honour (via LD_PRELOAD or library path injection). Fails on read-only
    # roots; succeeds where the target writes to /usr/local/lib or similar.
    exec_in "LD_PRELOAD writeability" \
      /bin/sh -c 'echo "/* fake */" > /usr/local/lib/vulbox-preload.so 2>/dev/null && \
                  ls -la /usr/local/lib/vulbox-preload.so'
    rc=$?
    ;;

  T1557)
    # AiTM precondition — old TLS/SSL still enabled? Detects images shipping
    # legacy openssl with SSLv3/TLSv1.0 enabled.
    exec_in "Legacy TLS check" \
      /bin/sh -c 'command -v openssl >/dev/null && \
                  openssl version | grep -E "(0\.9|1\.0\.0|1\.0\.1)" && exit 0; exit 1'
    rc=$?
    ;;

  *)
    # Unknown technique — non-exploitable rather than crash.
    echo ">>> [$TEST_ID] no implementation; treating as non-exploitable"
    rc=1
    ;;
esac

# Re-check container state. If exec broke it, return crash so the orchestrator
# rebuilds before the next test.
state_after=$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "missing")
if [[ "$state_after" != "running" ]]; then
  echo ">>> Sandbox state after test: $state_after — crash"
  exit 2
fi

exit "$rc"
