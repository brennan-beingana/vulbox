# Falco detection fix

## Problem (two layers)

1. **Launch bug (fixed earlier, commit de7154e).** Falco was passed a `--json`
   flag it doesn't have, so it exited non-zero before opening its output file.
   JSON is enabled via `-o json_output=true` only. Falco now launches cleanly,
   loads its driver ("modern BPF probe") and rules, survives startup, runs the
   full window, and exits on our SIGINT detach. Confirmed.

2. **No detections (this fix).** Falco ran fine but wrote **no `falco.json`**.
   Falco's `file_output` only creates the file once a rule actually matches — so
   during the whole run, not one rule fired on the ART activity. Likely cause:
   the container engine wasn't attaching container metadata to the docker-exec'd
   ART syscalls, so container-scoped stock rules (e.g. "Terminal shell in
   container") never tripped, and the rest of the stock set didn't match our
   specific commands either.

## What changed

- **`deploy/falco/vulbox_rules.yaml`** — self-contained VulBox rules tuned to the
  exact syscalls `scanners/atomic_runner.sh` produces, each MITRE-tagged:
  - `VulBox Sensitive File Read` — T1003 / T1552.001
  - `VulBox Host Filesystem Access` (`/proc/1/root`) — T1611
  - `VulBox Systemd Unit Write` — T1543.002
  - `VulBox Library Path Write` — T1574
  - `VulBox Pkexec Execution` — T1068
  - `VulBox Shell In Container` — T1059 / T1059.004
  - `VulBox System Information Discovery` — T1082

  The high-signal file read/write rules are **syscall-scoped, not
  container-scoped**, so they fire whether or not Falco attached container
  metadata — which is what guarantees `falco.json` now gets written. (Shell and
  discovery rules stay container-scoped to avoid host noise.)

- **`app/adapters/falco_adapter.py`** — `attach` now loads stock rules (whichever
  of `/etc/falco/falco_rules.yaml`, `…local.yaml`, `rules.d/` exist) plus the
  bundled VulBox rules via `-r` (`_rules_args`). The startup settle is raised to
  6s so the BPF driver is up before the first ART test runs (and a rules parse
  error is still caught as an early exit).

- **`docker/docker-compose.yml`** — the `--profile full` Falco sidecar mounts the
  rules file into `/etc/falco/rules.d/` so it auto-loads there too.

- **`scripts/falco_smoke.sh`** — empirical check (cleaned up from the original
  notes) for the Falco-enabled host.

## Host verification (Falco VM)

Code changes are validated by the unit suite (131 passing) and YAML parse, but
Falco itself isn't installed on the dev host, so confirm rule firing on the VM:

```bash
sudo scripts/falco_smoke.sh
```

Interpretation:
- Both the host read AND the container read alert → rules + engine OK.
- Host read alerts but the container one doesn't → container engine isn't
  attaching metadata (a Falco config issue, separate from these rules; our
  syscall-scoped rules still fire so detection works regardless).
- Nothing fires at all → rules didn't load; check the stdout log the script
  prints.
