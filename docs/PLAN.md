# authz.lock: final hackathon plan (Oct 20–29, 2026)

This plan is the result of the council review (`council/judge.md`, `security.md`, `scope.md`), with all of their findings applied. Deadline: **Thu 30 Oct, 10:30 PM IST**. Target: submit **Thu 29**, with a submittable build ready by **Mon 26**.
Track: Coding & Agentic Engineering, plus the Best Use of Tavily bonus.

## One-line pitch
A Nemotron agent (Token Factory) onboards an unfamiliar FastAPI app. It writes the seeder, the request hints and the regression tests, then repairs them until a deterministic engine can prove who can access what. Each PR diffs that "authz lockfile". **No LLM decides the verdict.**

## Architecture (two halves, one wall)
- **Deterministic core** (exists): `authzlock.py`, `probe_worker.py`. Its job is the lock → diff → PASS/FAIL/NEUTRAL decision. It imports nothing from `agent/`, and a test enforces this.
- **Agent layer** (`agent/`, new):
  - `tf.py`: Token Factory client. Base URL `https://api.tokenfactory.nebius.com/v1/`, retries with backoff, a $ cap per run, and a JSONL cost log.
  - `tools.py`: tool dispatch with the path jail.
  - `loop.py`: max-turns loop with forced `tool_choice`.
  - `cache.py`: artifacts keyed by base SHA, plus replay.
- **Models (two only):**
  - `nvidia/nemotron-3-super-120b-a12b` runs the agent loop.
  - `nvidia/Nemotron-3-Ultra-550b-a55b` makes one root-cause call per PR (a fix patch is a stretch goal).
  - Fall back to Ultra for the loop if the D1 smoke test shows Super tool-call failures above 10%.
- **Tavily**: angle 1 only. One `search` per FAIL finding, with `include_domains` set to owasp.org / cwe.mitre.org. Its output appears only in report prose. Angle 2 (auth-doc `extract`) runs only if app #2 onboarding stalls. Angle 3 is cut.

## App #2 (pinned now, judge #1)
**`eladgunders/fastapi-todos` @ `c059889336b7497ce80b9948a3720fb8c4b469e5`** (MIT).
- **Different auth stack:** fastapi-users 10.1.5 with a JWT bearer backend, UUID users, async SQLAlchemy 1.4 + asyncpg, Postgres 13, Python 3.9 image. The template uses hand-rolled JWT + SQLModel instead.
- **Per-user ownership:** `todos` and `categories` have a `created_by_id` column. There are also shared default categories (`created_by_id IS NULL`), which is a real policy question the manifest has to answer. Priorities are global.
- **Not seen yet** by `manifest.json`, the seeder or the hints.
- **Runtime:** it runs in its own venv/container (py3.9). The orchestrator never shares its interpreter.
- **Fallback if it misses its time-box** (Fri 23 to Sat 24 noon): delete the template's hand-written seeder and hints, and the agent re-onboards the template from scratch on camera.
- **Acceptance:** "agent onboards app #2 from zero: X/Y ops probed, base lock 0 violations, no code edits; one human-confirmed policy manifest". The template reproduction is a regression check (same 8/8 verdicts, coverage ≥ 20/22). It compares the decision matrix and invariants, never the raw lock, because canaries are random.
- **Video ablation:** app #2 without the agent gets 0 probes; with the agent it gets Y.

## Design rules (security BLOCKERs 1–5)
1. **Env allowlist for the worker.** The probe worker gets only `PATH`, `TZ`, `PYTHONWARNINGS`, `DATABASE_URL`, `SMTP_PORT`, plus the OS essentials (`SYSTEMROOT`, `HOME`, `LANG`). It never gets `NEBIUS_API_KEY` or `TAVILY_API_KEY`. Docker runs with `--network none`. *(Fixed D0: `authzlock.worker_env`.)*
2. **Workflow split.**
   - A: `pull_request` with `contents: read` and no secrets. It runs the deterministic probe using cached base artifacts and uploads `diff.json`.
   - B: `workflow_run`. It renders that artifact as untrusted data and posts the comment.
   - The agent (Nebius key) runs only on push to `main` or on `workflow_dispatch`. It commits the base-SHA artifacts.
   - Never `pull_request_target`. Demo PRs come from same-repo branches, and the fork policy is documented. Actions are pinned by SHA and use least-privilege `permissions:`.
3. **Base-only artifacts and seeder gates → NEUTRAL.**
   - Artifacts are generated from base and reused for head.
   - Policy (`public_operations`, `exceptions`, `privileged_identities`) is human-confirmed and read from the base branch only.
   - If the head edits the lock, manifest or workflow, the result is NEUTRAL.
   - Seeder gates: at least 2 non-privileged owners with canaried rows, and each owner's self-read is ALLOW and contains its canary. If a gate fails, the result is "harness invalid" (NEUTRAL), never PASS.
   - A coverage drop is NEUTRAL.
4. **Proof criteria come from JUnit XML, not exit codes.** A regression test counts as a proof only when all of these hold:
   - base passes;
   - head fails with an `AssertionError` raised inside the test;
   - the test references the finding's path and a canary;
   - writes stayed under `tests/authz/`;
   - the app source hash is unchanged.

   After at most 5 repair turns the finding is reported as "unproven".
5. **Prompt-injection containment.**
   - `write_file` is canonicalized and jailed to `.authzlock/artifacts/`.
   - The run tool accepts **fixed command templates** only (no free shell).
   - The sandbox has no secrets and no network.
   - Tavily output is wrapped as quoted data.
   - LLM/Tavily text only ever reaches report prose.
   - Every tool call is logged.

Also from the council:
- Escape everything in the comment and report: autoescape, CSP `default-src 'none'`, Markdown escaping, a ~60 KB cap, and redaction of JWTs and seeded passwords.
- A hard cap of **$1 per run**, with 429 backoff and jitter.
- File reads are truncated.
- A cached rerun costs $0 and makes 0 model calls.

## Threat model (of authz.lock itself)
- **Assets:** the Nebius and Tavily keys, the integrity of the verdict, and the repo's write token.
- **Untrusted inputs:**
  - PR code (it runs in-process with the probe);
  - repo text, docstrings and OpenAPI descriptions, which feed the agent;
  - Tavily pages;
  - LLM output.
- **Controls:** rules 1–5 above. Secrets never coexist with PR code. The LLM writes artifacts but never decides the verdict or the policy. Generated code runs only inside the container or sandbox.
- **Non-goal:** adversarial PR authors. PR code shares a process with the probe and could tamper with its output. authz.lock catches *accidental* regressions, such as AI-written BOLA, not malicious ones. The README states this.
- **Residual risks:**
  - The TestClient runs in-process (disclosed in the README).
  - `count_up` may give false positives on benign PRs that add fixtures. The benchmark measures this.

## Day plan (scope.md reorder; app #2 pulled forward per judge #1)
| Day | Deliverable | Exit check |
|---|---|---|
| D1 Tue 20 | **Gate:** one Super chat call + one forced tool call (`pytest -m live`). Billing route: promo code → Builders → international card → Discord. Request Sandboxes. Get Tavily key. Verify rules capture → `raw/rules_full_verified.md`. Attend Will It Ship (listen only). | Live smoke green, else D2 AM = billing only |
| D2 Wed 21 | Agent loop live: Super writes seeder + `param_hints` for the template via tools; cost log. | Same 8/8 verdicts, coverage ≥ 20/22 |
| D3 Thu 22 | Agent writes regression tests; repair loop with JUnit proof criteria (≤ 5 turns). **Billing hard checkpoint.** **Sandboxes go/no-go.** | 4/4 proofs |
| D4 Fri 23 | Ultra root cause + Tavily angle 1; Markdown PR comment; Action A/B on same-repo PR branches. **Demo URL live.** App #2 time-box starts (PM). | FAIL comment on a demo PR |
| D5 Sat 24 | **App #2 onboarding** (time-box ends noon) + injected IDOR PR → FAIL. Sandboxes used only to run proofs on base/head, if access exists. | App #2 lock, 0 violations; IDOR FAIL |
| D6 Sun 25 | Static HTML report (lock JSON → identity×op table, `<details>` evidence) on Pages; `--replay`; README v1 with measured $/PR and s/PR. Mutation benchmark (~10 patches across both apps). | Replay runs with no keys |
| D7 Mon 26 | **Submittable:** video v0 (unlisted), Devpost text, Built With, FEEDBACK v1, **Devpost draft saved**. | Draft saved |
| D8 Tue 27 | Harden: rerun 8 scenarios + app #2, clean-clone setup test (Dockerfile pinning py3.14), gitleaks. Stretch: Ultra fix patch → re-lock FAIL→PASS (judge #3). | Clean clone works |
| D9 Wed 28 | Final video (≤ 2:50, script for 2:40), final feedback. | Uploaded public |
| D10 Thu 29 | Checklist, submit by 6 PM IST. Fri 30 is buffer. | Submitted |

## Cuts (do not build)
- The Runner interface and Sandboxes probe sharding. `ponytail:` sharding is the upgrade path.
- A third model (Lightning/Nano).
- Tavily angles 2 (unless needed) and 3.
- A click-through JS report. The static HTML is enough.
- `/authz accept`, Telegram, multi-tenant support.
- Per-finding Ultra calls. Use one per PR.

## Tests (scope.md d)
| # | Test | Status |
|---|---|---|
| 1 | `test_tf_client_uses_nebius_base_url` (base_url, `^nvidia/`) | D0 |
| 2 | `test_live_tf_smoke` (marked `live`; skipped without a key) | D0 (skips) |
| 3 | `test_tool_dispatch_rejects_unknown_tool_and_path_escape` | D0 |
| 4 | `test_agent_loop_terminates_at_max_turns` (stub model) | D0 |
| 5 | `test_cost_logger_records_model_tokens_usd_latency` + budget cap | D0 |
| 6 | `test_verdict_independent_of_llm` (AST import check + same diff) | D0 |
| 7 | `test_artifact_cache_keyed_by_sha` (2nd run = 0 calls) | D0 |
| 8 | `test_generated_seeder_reproduces_8_scenario_verdicts` (integration, Postgres) | D2 |
| 9 | `test_repair_loop_accepts_only_pass_base_fail_head` (JUnit) | D3 |
| 10 | `test_tavily_called_once_per_fail_with_domain_restriction` (+ live) | D4 |
| 11 | `test_pr_comment_renders_fail_table_test_and_report_link` (+ escaping) | D4 |
| 12 | `test_replay_mode_runs_without_api_keys` | D0 |
| 13 | `test_no_secrets_in_repo` | D0 |
| + | `test_worker_env_excludes_secrets` (security #1) | D0 |

## Known open questions
- The Token Factory prices in `agent/tf.py` are placeholders. Verify them on D1 from the pricing page, because the $ cap depends on them.
- The contree-sdk (Sandboxes) pins py3.12. If used, run it in its own venv/subprocess.
