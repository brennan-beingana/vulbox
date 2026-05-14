# vulnerable_target — INTENTIONALLY VULNERABLE

**Do not deploy.** This directory is a fixture used only by VulBox's end-to-end
test suite (`pytest -m e2e`). Every piece of it is deliberately exploitable so
the pipeline produces deterministic Trivy findings and at least one successful
Atomic Red Team exploitation.

## What's vulnerable

- **`node:14-alpine` base image** — end-of-life, ships with known CVEs in
  OpenSSL, busybox, and the Node 14 runtime.
- **`express@4.16.0`** — pinned to a version with disclosed CVEs.
- **`lodash@4.17.20`** — vulnerable to CVE-2020-8203 (prototype pollution via
  `_.merge` / `_.set`).
- **`/exec?cmd=...`** — passes the query string straight into `eval()`. Maps to
  MITRE ATT&CK T1059 (Command and Scripting Interpreter).
- **`/merge`** — accepts an arbitrary JSON body and `_.merge`s it into a fresh
  object, exercising the lodash prototype-pollution CVE.

## Why it's committed to the repo

The plan in `demo_revamp.md` (Deliverable A) requires deterministic E2E
results. Pointing the pipeline at an external repo means upstream drift turns
"all tests pass" into a coin flip. Bundling the target in-tree pins the inputs.

## How it's used

`tests/e2e/conftest.py` copies this directory into a temp dir, runs
`git init && git add && git commit`, and hands the resulting `file://` URL to
`POST /runs`. `DockerManager.clone_repo` then clones it with
`git clone --depth 1`, builds the Docker image, and the rest of the pipeline
takes over.
