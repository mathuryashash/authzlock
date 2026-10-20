# authz.lock — working prototype (deterministic core)

authz.lock records **who can access what** in a FastAPI app as a lockfile. It logs in as every kind of user, calls every endpoint against every other user's data, and writes down the result. On each PR it re-runs everything on base and head and diffs the two lockfiles.

This prototype is only the **deterministic verdict engine**. The target app is `fastapi/full-stack-fastapi-template`, pinned to commit `cb740b6`.

## What is real vs. not built yet

| Part | Status |
|---|---|
| Seed identities and owned data with per-run random canary tokens | Built (rule-based seeder) |
| Real login for normal users; minted tokens for forged, expired, `alg:none`, deleted and inactive users | Built |
| Operation discovery from the app's own OpenAPI | Built |
| Request synthesis (path params, JSON and form bodies, hostile mass-assignment variant) | Built (rule-based) |
| One fresh Postgres clone per probe (`CREATE DATABASE … TEMPLATE`) and a row-level DB diff with owner attribution | Built |
| Leak detection in responses (JSON and CSV), plus an SMTP sink for leaks sent by email | Built |
| Invariants I1–I6, the lockfile, base-vs-head diff, PASS/FAIL/NEUTRAL | Built |
| Regression pytest per finding, **proven** to pass on base and fail on the PR | Built (4 fixed patterns) |
| Nemotron agent that *writes* the seeder, requests and tests and repairs them | **In progress.** Agent layer built and stub-tested (see below); live runs need a Token Factory API key |
| Running regression proofs inside Token Factory Sandboxes (`--runner sandbox`) | **Built, live 4/4** (`results/sandbox_run1/`). The probe worker itself still runs locally |
| GitHub Action, `/authz accept`, HTML report, Telegram notifier | **Not built** |

## Results (2-core cloud VM, Postgres 16, Python 3.14.7)

The base lock has 603 probes across 22 operations and takes about 100 s. The base lockfile has 0 invariant violations.

| Scenario | Expected | Got | What fired |
|---|---|---|---|
| Same SHA run twice (fresh seed, fresh random canaries) | PASS | **PASS** | 0 changed cells |
| Benign: default page size 100 → 50 | PASS | **PASS** | 0 changed cells |
| Benign: new owner-scoped `GET /items/stats` | PASS | **PASS** | New op, invariant-clean |
| Refactor drops ownership check on `GET /items/{id}` | FAIL | **FAIL** | I1 read-isolation; 4 cells DENY→ALLOW |
| AI-written `GET /items/export` CSV with no owner filter | FAIL | **FAIL** | I1 on a *new* endpoint (no baseline needed) |
| `is_superuser` added to the `/users/me` update schema | FAIL | **FAIL** | I4 privilege (via the hostile-body variant) |
| "Simplified" count query | FAIL | **FAIL** | Count 7→14 and 3→14 (numeric side channel) |
| Same code, template's dev `.env` vs production profile | FAIL | **FAIL** | Unauthenticated `POST /private/users/` appears (I3, I5) |

**Regression tests.** For all 4 FAIL PRs, the generated test passes on base and fails on the PR (`results/regression_proofs.json`). For the export PR, the base pass is trivial because the endpoint doesn't exist there yet.

**Coverage is 20/22 operations.** Two operations were not probed:

- `POST /reset-password/` needs a valid reset token. That's a job for the future agent.
- `POST /password-recovery-html-content/{email}` crashes. The template sets an invalid response header name, `"subject:"`. That's a real bug in the template that the probe surfaced incidentally. It's recorded as INCONCLUSIVE, never green.

## Run it natively on Windows (measured: base lock 603 probes in ~38 s, 8 scenarios in ~6.5 min)

Postgres in Docker (`docker run -d -p 5433:5432 --tmpfs /var/lib/postgresql/data -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16 -c fsync=off`), the template checked out to `target/` as in `setup.sh` with `uv sync --python 3.14` (its `.venv\Scripts\python.exe` is picked up automatically), then:

```bash
export AUTHZ_PG=postgresql://postgres@127.0.0.1:5433/postgres
python -m agent.onboard target                        # needs NEBIUS_API_KEY; writes target/.authzlock/artifacts/
python run_scenarios.py target .authzlock/agent_scen target/.authzlock/artifacts/manifest.json target/.authzlock/artifacts/seeder.py
python run_scenarios.py target .authzlock/ref/scen manifest.json seeders/fullstack_template.py   # hand-written reference
python compare.py .authzlock/ref/scen .authzlock/agent_scen   # decision matrix + invariants + verdicts
```

## Run it yourself (Linux or WSL2 Ubuntu)

```bash
./setup.sh                                    # Postgres via Docker, pins the template, creates the 6 PR branches, Python 3.14 env
python3 run_scenarios.py target               # about 15 min: base lock, determinism, 6 PRs, dev profile
python3 regress_tests.py target results target.env   # proves each generated test: pass on base, fail on PR
```

Reports land in `results/*.report.md`. To diff any two lockfiles:

```bash
python3 authzlock.py diff --base results/base_run1.lock.json --head results/pr_idor_refactor.lock.json
```

## Decision rule and invariants

- **Decision:**
  - ALLOW = 2xx/3xx, *or* any foreign-data leak, *or* any foreign DB change.
  - INCONCLUSIVE = 5xx or a crash.
  - DENY = any other 4xx. The template uses 400 for inactive users.
- **I1 read isolation:** a non-superuser never receives another owner's canaries.
- **I2 invalid-identity writes:** invalid identities never modify data.
- **I3 write isolation:** no changes to other owners' rows, and no account creation outside the declared public signup.
- **I4 privilege:** privilege columns (`is_superuser`, `is_active`) only change when a superuser makes the request.
- **I5 authn:** forged, expired, `alg:none`, deleted, inactive and anonymous identities are never ALLOWed on non-public operations.
- **I6 out-of-band:** no email carries another owner's data.

## Built during Oct 20–29, 2026 (Nebius x NVIDIA Global AI Hackathon)

The deterministic core above is the pre-hackathon prototype (25 Sep). During the hackathon it gained the following. See `docs/PLAN.md` for the full plan and threat model.

| Part | Status |
|---|---|
| `agent/` Token Factory client: base URL, Nemotron Super/Ultra, retries/backoff, $1 cap per run, JSONL cost log | Built (stub-tested; live test waiting on API key) |
| Tool dispatch: `write_file` jailed to `.authzlock/artifacts/`, fixed command templates, all calls logged | Built |
| Agent loop: forced `tool_choice`, max-turns cap | Built |
| Artifact cache per base SHA, keyless replay | Built |
| Worker env allowlist (API keys never reach PR code) | Built |
| **Onboarding agent** (`agent/onboard.py`): Nemotron Super reads the app's OpenAPI + source and writes `manifest.json` (identities, ownership, `param_hints`, policy proposal) and `seeder.py` into `.authzlock/artifacts/`, runs the base lock through the fixed `lock_artifacts` template and repairs until the harness is valid | **Built, live.** Run 1: 14 turns, $0.051, 2m17s. With *only* the agent's artifacts: **8/8 scenario verdicts, 603/603 identical decision cells, 0 invariant diffs, coverage 20/22** (`results/agent_run1/`) |
| Seeder gates (security #3): ≥2 non-privileged owners with canaried rows (counted by the worker from the seed DB) that read their own canary back; else "harness invalid" → NEUTRAL | Built |
| **Regression-test agent** (`agent/regress.py`): Super writes `tests/authz/test_regression.py` per FAIL finding into the artifacts jail, runs the fixed `prove` template (`regress_run.py`: worktree of base and head, fresh DB, pytest `--junitxml`, key-free env), and repairs until `proof.py` holds (base passes; head fails with an AssertionError inside the test; path + canary referenced; writes only under `tests/authz/`; app source hash unchanged). Max 5 prove runs, else `unproven`. Benign PRs get no test and no model call | **Live 4/4 proven** (`results/agent_regress2/`: count-leak, export-csv, idor-refactor, mass-assign each proven in 2 prove runs, 9-15 turns; both benign PRs: no test, no model call; whole run $0.089, 47 calls) |
| Tavily angle 1 (`agent/tavily.py`): one OWASP/CWE-allowlisted search per FAIL finding, quoted in report prose only | Built (stub-tested; wired into the report on D4) |
| Ultra root cause (one call per FAIL, quoted DATA, never read by verdict code) + Tavily OWASP/CWE citations; Markdown PR comment (`comment.py`: escapes `\|`, backticks, `<`, `@`, `](`; redacts JWTs/passwords; 60 KB cap) | **Built** (live on idor: CWE-639 + OWASP API1:2023 cited; sample comment `results/agent_regress1/pr-idor-refactor.comment.md`) |
| GitHub Actions split (security #2): `authz-probe` (`pull_request`, `contents: read`, no secrets, engine/policy/artifacts from base SHA, PR may only change `demo/`) → `diff.json`; `authz-comment` (`workflow_run`, renders the untrusted artifact, same-repo PRs only); `authz-agent` (push to main / dispatch, Nebius key). SHA-pinned | **Live on GitHub**: demo PR [#1](https://github.com/mathuryashash/authzlock/pull/1) (IDOR) → probe green, comment ❌ FAIL (I1 read-isolation on `GET /items/{id}`); PR [#2](https://github.com/mathuryashash/authzlock/pull/2) (benign) → ✅ PASS. Probe ~1m50s. `authz-agent` not re-run yet |
| **Second app** (D5): `eladgunders/fastapi-todos` @ `c059889` (fastapi-users JWT, async SQLAlchemy, int ids, link table, shared NULL-owner rows, Python 3.9) | **Live.** See *App #2* below |
| Static HTML report; mutation benchmark ($/PR, s/PR, detection rate) | Planned (D6) |

Run the agent-layer tests (any OS):

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-agent.txt   # Windows: .venv\Scripts\pip
python -m pytest -q            # live tests auto-skip without NEBIUS_API_KEY
```

**Sandboxes runner** (`sandbox_run.py`, `--runner sandbox|local`, local is the default and what CI uses). One snapshot per (app, base SHA, recipe hash): `python:3.14-slim` + Postgres 17 + the app's `uv.lock` deps, built once (~50 s) and reused by tag. Each proof uploads `git archive <ref> backend` (committed tree only), the test and `target.env` via `files=`, and runs pytest `--junitxml` in a **disposable** VM; `proof.py` is unchanged. Base and head, and all scenarios, run concurrently.

```bash
.venv/Scripts/python sandbox_run.py target .authzlock/agent_scen results/agent_regress2 results/sandbox_run1 --runner sandbox
.venv/Scripts/python -m agent.regress target .authzlock/agent_scen out --runner sandbox     # agent loop proves in sandboxes
```

| 4 FAIL proofs (same agent-written tests) | Proven | Wall time |
| --- | --- | --- |
| local (Windows, one Postgres, serial) | 4/4 | 44.7 s (11-14 s each) |
| sandbox, warm snapshot, 8 VMs concurrent | 4/4 | 12.2 s (11-12 s each; pytest itself < 1 s) |
| sandbox, cold (first build) | 4/4 | 54 s build + ~17 s per proof |

**Threat model (short):** authz.lock catches *accidental* authorization regressions, not adversarial PR authors, because PR code runs in-process with the probe. Secrets never share a process with PR code or generated code. The LLM writes artifacts but never decides the verdict or the policy. With `--runner sandbox`, PR code and generated tests run in a Nebius VM that gets **no `env=`** (0 NEBIUS/TAVILY/GITHUB vars visible inside) and **no network**: every proof spawn sets `networking.enabled=false` (no `eth0`, egress blocked; confirmed in the server-side operation records, `results/sandbox_run1/network_and_env.txt`). Egress is **open by default** on Sandboxes and contree-sdk 0.3.6 has no parameter for it, so the runner injects the field into the spawn body; only the one-time snapshot build (apt, PyPI) runs with network on, from host-pinned inputs (`uv.lock`), never PR code. The API key stays in the host process.

## App #2: fastapi-todos, agent-written artifacts only (D5)

The onboarding agent (Nemotron Super) wrote `manifest.json` + `seeder.py` from the app's OpenAPI and source. **0 human
edits** to them (`results/app2/HUMAN_EDITS.md`). Humans wrote only the infra profile (`apps/todos/profile.json`: how
to boot/migrate/test, pins) and the 3 planted PRs.

| | Result |
|---|---|
| Base lock (agent artifacts, run 5) | 639 probes, harness valid, **coverage 17/20** (unprobed: `DELETE /users/{id}`, `POST /auth/reset-password`, `POST /auth/verify`; they need a superuser target / emailed tokens), 0 violations. Same SHA twice: 0 changed cells |
| `pr-todo-get-by-id` (new endpoint, no owner filter) | ❌ FAIL, I1 read-isolation |
| `pr-category-cleanup` (non-owners may delete default categories) | ❌ FAIL, I3 write-isolation on `shared` rows |
| `pr-todos-completed-filter` (benign) | ✅ PASS, no test, no model call |
| Regression tests, agent loop live with `--runner sandbox` (python:3.9-slim + PG snapshot, no network) | **2/2 proven** in Sandboxes: todo IDOR (2 prove runs, 11 turns), default-category delete (1 prove run, 6 turns). Needed 3 sandbox runs; failures 1-2 led to `regress.py` fixes (API prefix + test file list in the prompt, mis-placed writes refused, junit failure messages fed back). `results/app2/acceptance.json` |
| LLM spend for D5 | $1.14 total (5 onboarding runs $0.97, 3 regress runs $0.17) |

It took 5 onboarding runs. Each failure became an engine fix with a test, never a hand-edit to an artifact. The fixes:
- a per-app profile replaces the `backend/` and `app.api.deps` assumptions;
- the seeder runs in a subprocess, because async engines leaked across event loops;
- seeded identity flags are checked against the manifest;
- artifacts are validated on write;
- the last green artifacts are kept;
- NULL-owner rows are always probed as target `shared`.

App #1's lock is unchanged: 603/603 cells identical.

**Policy question raised by shared default categories.** fastapi-todos seeds categories with `created_by_id = NULL`.
Every user can read them and nobody may delete them. Which reading is right?
- They are system rows. A non-owner deleting one is a write-isolation break, which is what authz.lock flags.
- They are per-user clutter that users may hide or remove.

authz.lock cannot know. It records base behaviour (403 for everyone, superuser included) as the lock. A PR that
changes it fails until a maintainer accepts the decision. A real deployment would put this in the policy as an explicit
`exceptions` entry, or move hiding to a per-user link table so the shared row is never mutated.

## Known limitations of this prototype

- The seeder, parameter mapping (`manifest.json` → `param_hints`) and test patterns are hand-written for this template. Generalising them is the agent's job.
- Probes run in-process with Starlette's TestClient, one process per SHA. The production design runs the app as a separate process and OS user inside a sandbox. Only the regression proofs run in Sandboxes so far, not the probe worker.
- The Sandboxes guest kernel has no SysV shared memory (`shmget` -> ENOSYS), so Postgres needs `sandbox/shmshim.c` (LD_PRELOAD, fakes its one interlock segment) plus `shared_memory_type=mmap`. Fine for a throwaway test DB, not a production Postgres.
- Single-tenant, per-user ownership only. Time-based and sharing rules are out of scope.
