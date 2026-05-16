● Strategic plan: scale the CVE→technique map and validation surface

  Where we are today

  ┌──────────────────────────────────────────────┬─────────────────────┬────────────────────────────────────────────────┬──────────────┐
  │                   Surface                    │       Current       │               ART/industry scale               │     Gap      │
  ├──────────────────────────────────────────────┼─────────────────────┼────────────────────────────────────────────────┼──────────────┤
  │ CVEs explicitly mapped                       │ 55                  │ CISA KEV alone: ~1,100; NVD: 250k+             │ ~20× under   │
  │ (cve_technique_map.yml)                     │                     │                                               │ KEV           │
  ├─────────────────────────────────────────────┼─────────────────────┼───────────────────────────────────────────────┼───────────────┤
  │ Techniques in map                           │ 14                  │ ATT&CK Enterprise: ~200 base, ~700 with       │ ~15× under    │
  │                                             │                     │ sub-techniques                                │               │
  ├─────────────────────────────────────────────┼─────────────────────┼───────────────────────────────────────────────┼───────────────┤
  │ Techniques with runnable tests              │ 12 (hand-rolled     │ Atomic Red Team: ~700 atomic tests            │ ~50× under    │
  │ (atomic_runner.sh)                          │ bash)               │                                               │               │
  ├─────────────────────────────────────────────┼─────────────────────┼───────────────────────────────────────────────┼───────────────┤
  │ Heuristic fallbacks                         │ 7 keyword rules     │ —                                             │ n/a           │
  ├─────────────────────────────────────────────┼─────────────────────┼───────────────────────────────────────────────┼───────────────┤
  │ Refresh cadence                             │ manual YAML edits   │ KEV updates ~weekly                           │ no automation │
  └─────────────────────────────────────────────┴─────────────────────┴───────────────────────────────────────────────┴───────────────┘
  
  The map is curated by intuition (well-known CVEs that come to mind) and the "runner" is a bash imitation of ART, not a call into ART. To
  get real validity gains we need authoritative data and a real executor.

  ---
  Phase 1 — Ingest authoritative CVE→technique sources
  
  Stop hand-curating. Pull from three feeds and normalize them into the existing YAML schema.

  1. CISA KEV catalog — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json. ~1,100 CVEs known to be
  exploited in the wild. Highest signal for "this matters" but no ATT&CK technique field — must be joined.
  2. Center for Threat-Informed Defense attack_to_cve — github.com/center-for-threat-informed-defense/attack_to_cve. Curated CVE→ATT&CK
  technique mappings with confidence scores. This is the single best source for direct mappings.
  3. NVD JSON feeds — nvd.nist.gov/feeds/json/cve/2.0/. Every CVE carries a CWE. Use CWE as a bridge (Phase 3) for the long tail where no
  direct technique mapping exists.
  
  Deliverable: scripts/build_cve_map.py that reads the three feeds, merges them, and emits data/cve_technique_map.yml. Existing manual
  entries stay in a separate data/cve_technique_map.overrides.yml so generated and human-curated data don't fight.

  Expected output: ~1,500 high-confidence CVE→technique entries on day one (KEV ∪ attack_to_cve).
  
  Phase 2 — Replace the bash runner with real Atomic Red Team

  The current scanners/atomic_runner.sh is a 12-technique bash imitation. Swap it for atomic-operator (Python wrapper around the official
  atomics tree — github.com/swimlane/atomic-operator). Reasons:

  - Pulls the canonical redcanaryco/atomic-red-team atomics tree (~700 tests).
  - Pure Python, integrates cleanly with our FastAPI stack and async orchestrator.
  - Each technique has multiple test_number variants; the wrapper handles prereq checks, executor selection (bash/sh/powershell), and
  cleanup commands.
  
  Adapter change: ARTAdapter.execute_test(technique_id) becomes atomic_operator.Atomic().run(technique=technique_id, test_numbers=[...])
  with the variant selected from image fingerprint (Linux distro, package manager presence). The bash file stays only for a small set of
  "container-native" probes (T1611 host-filesystem read, T1543.002 systemd write) that ART doesn't cover natively.

  Phase 3 — CWE→technique bridge for the long tail

  Direct CVE→technique mappings exist for ~thousands of CVEs; the other ~240k mostly carry a CWE. Add a data/cwe_technique_map.yml
  (one-time human curation, ~200 entries covers >95% of CWE volume), e.g.:

  - cwe: CWE-78    # OS Command Injection
    technique: T1059
  - cwe: CWE-269   # Improper Privilege Management
    technique: T1068
  - cwe: CWE-22    # Path Traversal
    technique: T1083

  Adapter resolution order: direct CVE map → CWE bridge → keyword fallback (today's mechanism).
  
  Phase 4 — Confidence-weighted scoring
  
  Each mapping carries a provenance: direct_curated, direct_kev, cwe_bridge, keyword. Threading this through to SecurityMatrixEntry:
  
  - Tests fire in provenance order (highest confidence first), so the early test budget is spent on high-signal pairs.
  - _compute_risk already caps at 50; add a -5 penalty when the test that "exploited" came from a keyword fallback — prevents the report
  from over-claiming on weak signals.
  - Surface provenance in /reports/{id} so the dashboard can render "high-confidence exploit" vs "heuristic match".

  Phase 5 — Freshness

  A weekly GitHub Action (ci/refresh-cve-map.yml):
  
  1. Re-runs scripts/build_cve_map.py.
  2. Diffs against checked-in YAML.
  3. Opens a PR titled chore: refresh CVE map (YYYY-MM-DD).

  Plus pin atomic-red-team to a SHA in requirements.txt so the test set is reproducible across runs.
  
  Phase 6 — Validation harness (the "is this thing accurate?" part)

  The biggest gap in claiming "validity" is that today nothing measures whether VulBox's exploit verdicts are correct. Build a ground-truth
   corpus:

  - 20–30 deliberately vulnerable images from Vulhub (github.com/vulhub/vulhub) — each has a known-exploitable CVE and a documented PoC.
  - A pytest suite (tests/e2e_ground_truth.py, opt-in, marked slow) that runs the full pipeline against each and asserts the expected
  technique resolves to exploited=True.
  - Track precision and recall over time in a generated docs/validation-report.md. Every map refresh PR includes a delta.

  This is the single most credible "validity" claim you can make in writeups: "VulBox correctly identifies exploitability on X/Y 
  known-vulnerable images."

  ---
  Suggested sequencing (concrete sprint plan)

  ┌────────┬─────────────────────────────────────────────────────────────────────────┬──────────┐
  │ Sprint │                               Deliverable                               │  Effort  │
  ├────────┼─────────────────────────────────────────────────────────────────────────┼──────────┤
  │ 1      │ scripts/build_cve_map.py ingesting KEV + attack_to_cve → ~1,500 entries │ 1–2 days │
  ├────────┼─────────────────────────────────────────────────────────────────────────┼──────────┤
  │ 2      │ Swap atomic_runner.sh for atomic-operator; adapter rewrite              │ 2–3 days │
  ├────────┼─────────────────────────────────────────────────────────────────────────┼──────────┤
  │ 3      │ cwe_technique_map.yml + bridge resolution in adapter                    │ 1 day    │
  ├────────┼─────────────────────────────────────────────────────────────────────────┼──────────┤
  │ 4      │ Provenance field on map entries + risk-score weighting                  │ 1 day    │
  ├────────┼─────────────────────────────────────────────────────────────────────────┼──────────┤
  │ 5      │ GitHub Action for weekly refresh PR                                     │ half-day │
  ├────────┼─────────────────────────────────────────────────────────────────────────┼──────────┤
  │ 6      │ Ground-truth corpus with 5 Vulhub images, then expand                   │ 2–3 days │
  └────────┴─────────────────────────────────────────────────────────────────────────┴──────────┘

  Risks / open questions

  - Atomic tests can be destructive. Already mitigated by sandbox isolation, but expanding to 700 tests means hardening the sandbox
  teardown path — verify rebuild path actually triggers on crash_occurred.
  - License / vendoring. ART atomics are MIT; we can either pin the repo at runtime (lighter) or vendor (reproducible offline). Worth a
  decision early.
  - False positives blow up. Going from 55 → 1,500 mappings will surface tests on images that "have the package" but aren't actually
  vulnerable. Phase 4's provenance weighting is the main mitigation; Phase 6's ground-truth measurement is how you'd know.
  
  ---
  Want me to start on Sprint 1 — write scripts/build_cve_map.py that pulls KEV + the Center's attack_to_cve mappings and regenerates
  data/cve_technique_map.yml? That's the highest leverage step and unblocks everything after it.

✻ Cogitated for 1m 48s

❯ how do you think I should go about the remediation guidance concept?                                                                     

● Let me see what's already in the remediation layer before forming an opinion.

  Read 2 files, listed 1 directory (ctrl+o to expand)

● Now I've seen the full stack — remediation_service.py (4 canned rules) plus llm_remediation.py (OpenAI-driven, evidence-grounded, cached,
   schema-validated). It's a solid skeleton. Here's where I think the leverage is, ranked by impact.

  What's already good

  - LLM gets real evidence (ART log, Falco rules, CVE) — not just the CVE id.
  - Untrusted-evidence handling (the <evidence> tag pattern) is correct.
  - Static fallback is hard-wired in three places (disabled, API fail, malformed JSON) — no silent gaps in the report.

  So the question isn't "do we add LLMs", it's "what makes the output trusted and actionable enough to justify the LLM call".

  My recommended direction, ranked

  1. Cluster before you remediate (biggest single win)

  Today every SecurityMatrixEntry gets its own row. A real image will yield ~80 glibc CVEs, ~20 openssl CVEs, all collapsing to two or
  three real fixes. The report becomes noise.

  Group entries by (package, fix_version) before generating remediations. One LLM call per cluster, not per CVE. The Remediation row gets
  an array of matrix_entry_ids it covers. The dashboard renders:

  ▎ Upgrade glibc to 2.39 — fixes 47 findings, neutralizes T1068 + T1574 exploit paths.

  This alone makes the report feel professional instead of overwhelming, and it cuts LLM cost ~10–20×.

  2. Stop relying on LLM recall for fix versions — inject canonical fix data

  gpt-4o-mini will confidently tell you "upgrade openssl to 3.0.12" when the actual fix is 3.0.15. The model shouldn't be recalling fix
  versions; it should be synthesizing prose around facts you give it.

  Add a FixDataSource that pulls per-CVE fix info from:
  - OSV.dev (api.osv.dev/v1/vulns/{cve}) — has affected/fixed version ranges in a structured format, covers most ecosystems.
  - GitHub Security Advisories for npm/pypi/etc.
  - NVD references as a last resort.
  
  Pass the structured fix into the prompt:

  Canonical fix (from OSV.dev): upgrade openssl from 3.0.11 → 3.0.15
  References: <list of pre-resolved URLs>

  The LLM's job becomes "write the remediation in the user's voice around this fact." Hallucination risk drops massively, and references
  stops being trust-me URLs.

  3. Tier the output for different audiences

  One blob of text serves nobody. Three small fields cost the same prompt-tokens but read very differently:

  {
    "executive_summary": "...",   // 1 sentence: what & risk
    "developer_action": "...",    // concrete commands / Dockerfile diff
    "security_context": "..."     // why it matters, detection coverage
  }

  The dashboard can collapse/expand these. Same LLM call, much better artifact.

  4. Produce a patch, not a paragraph

  This is the leap from "advice" to "fix". For container findings, the actionable output is almost always:

  - A Dockerfile diff (FROM debian:bullseye → bullseye-20250114-slim, or pin apt-get install glibc=2.39-...).
  - A package manifest bump (package.json, requirements.txt, go.mod).
  - A runtime hardening snippet (seccomp profile, --read-only, drop capabilities) for T1611.

  Emit these as a remediation_patch field — even a unified diff string — alongside the prose. That's what makes a remediation usable in a
  PR review.

  5. Close the loop with re-validation

  The single biggest credibility move: after generating remediation, offer "Apply & re-test". The orchestrator already has REBUILDING in
  its state machine; wire a POST /runs/{id}/revalidate that:

  1. Builds a new image with the suggested fix applied (or accepts a user-supplied tag).
  2. Re-runs only the techniques that previously exploited.
  3. Shows a before/after matrix.

  This is what turns the tool from "scanner that nags you" into "scanner that proves the fix worked." It's also the most defensible
  methodology for a writeup/demo.

  6. Per-technique prompt templates

  Today the system prompt is technique-agnostic. But the shape of the right answer varies a lot:

  - T1059 (RCE) — input validation, WAF rule, dependency pin
  - T1068 (privesc) — drop SUID, runtime user, polkit policy
  - T1611 (escape) — user namespaces, seccomp, no --privileged
  - T1552 (creds in files) — secret store, file perms, env vars

  Have ~10 small "technique briefings" injected as additional system context per call. Cheap, sharply improves specificity.

  7. Give the model image context

  Right now the prompt doesn't tell the model what the image is. DockerManager knows base image, distro, package manager. Include it:

  Image: my-app:latest (base: python:3.11-slim, distro: debian/bookworm, pkg manager: apt)

  That's the difference between generic Linux advice and "edit /etc/apt/sources.list to pin this version."

  ---
  Suggested phasing

  ┌───────┬──────────────────────────────────────┬──────────────────────────────────────────────────────────────────┐
  │ Phase │                 Work                 │                            Why first                             │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 1     │ Clustering by (package, fix_version) │ Cheapest, biggest UX/cost win                                    │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 2     │ OSV.dev fix-data injection           │ Removes hallucination risk on the one thing that has to be right │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 3     │ Tiered output (exec/dev/security)    │ Same call, better artifact                                       │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 4     │ Image context in prompt              │ Tiny code change, large quality bump                             │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 5     │ Per-technique briefings              │ Once you have evidence the prose is too generic                  │
  That's the difference between generic Linux advice and "edit /etc/apt/sources.list to pin this version."

  ---
  Suggested phasing

  ┌───────┬──────────────────────────────────────┬──────────────────────────────────────────────────────────────────┐
  │ Phase │                 Work                 │                            Why first                             │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 1     │ Clustering by (package, fix_version) │ Cheapest, biggest UX/cost win                                    │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 2     │ OSV.dev fix-data injection           │ Removes hallucination risk on the one thing that has to be right │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 3     │ Tiered output (exec/dev/security)    │ Same call, better artifact                                       │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 4     │ Image context in prompt              │ Tiny code change, large quality bump                             │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 5     │ Per-technique briefings              │ Once you have evidence the prose is too generic                  │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 6     │ Patch generation (Dockerfile diff)   │ Moves from advice → action                                       │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 7     │ Apply & re-test endpoint             │ The thesis-grade credibility move                                │
  └───────┴──────────────────────────────────────┴──────────────────────────────────────────────────────────────────┘

  Two anti-patterns to avoid

  - Don't make the LLM a primary source of truth. Every fact (fixed version, CVE severity, advisory URL) should come from a structured feed
   you control. The LLM is a writer, not a database.
  - Don't tier confidence by LLM presence. The static row currently gets confidence from a rule; the LLM row gets confidence from the
  model. The model will overclaim. Compute confidence from (provenance of CVE→technique mapping, exploited, detected, has-canonical-fix) —
  outside the LLM — and pass it in as a constraint.


  ┌───────┬──────────────────────────────────────┬──────────────────────────────────────────────────────────────────┐
  │ Phase │                 Work                 │                            Why first                             │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 1     │ Clustering by (package, fix_version) │ Cheapest, biggest UX/cost win                                    │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 2     │ OSV.dev fix-data injection           │ Removes hallucination risk on the one thing that has to be right │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 3     │ Tiered output (exec/dev/security)    │ Same call, better artifact                                       │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 4     │ Image context in prompt              │ Tiny code change, large quality bump                             │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 5     │ Per-technique briefings              │ Once you have evidence the prose is too generic                  │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 6     │ Patch generation (Dockerfile diff)   │ Moves from advice → action                                       │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 7     │ Apply & re-test endpoint             │ The thesis-grade credibility move                                │
  └───────┴──────────────────────────────────────┴──────────────────────────────────────────────────────────────────┘

  Two anti-patterns to avoid

  - Don't make the LLM a primary source of truth. Every fact (fixed version, CVE severity, advisory URL) should come from a structured feed
   you control. The LLM is a writer, not a database.
  - Don't tier confidence by LLM presence. The static row currently gets confidence from a rule; the LLM row gets confidence from the
  │ 5     │ Per-technique briefings              │ Once you have evidence the prose is too generic                  │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 6     │ Patch generation (Dockerfile diff)   │ Moves from advice → action                                       │
  ├───────┼──────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
  │ 7     │ Apply & re-test endpoint             │ The thesis-grade credibility move                                │
  └───────┴──────────────────────────────────────┴──────────────────────────────────────────────────────────────────┘

  Two anti-patterns to avoid

  - Don't make the LLM a primary source of truth. Every fact (fixed version, CVE severity, advisory URL) should come from a structured feed
   you control. The LLM is a writer, not a database.
  - Don't tier confidence by LLM presence. The static row currently gets confidence from a rule; the LLM row gets confidence from the
  model. The model will overclaim. Compute confidence from (provenance of CVE→technique mapping, exploited, detected, has-canonical-fix) —
  outside the LLM — and pass it in as a constraint.

  Known gaps (worth flagging)

  - 59 of 97 mapped techniques have no upstream YAML at all — they're umbrella technique IDs (T1068, T1190, T1574, T1211, etc.) that ART
  only models via sub-techniques or not at all. Bash covers the high-value ones (T1068 via pkexec, T1190 via HTTP probe, T1611 via
  /proc/1/root, T1574 via LD_PRELOAD writability) — but the long tail of T-codes from the CWE bridge will just no-op.
  - 17 techniques have YAMLs but no Linux variants (e.g. T1003 — all 7 ART tests are Windows). The bash file's T1003 probe (cat
  /etc/shadow) substitutes here, so no regression.
  - No real container exercised yet. The whole chain is unit-tested but end-to-end against a live target-app image is still a manual
  scripts/demo.py run. Worth doing before the next milestone.