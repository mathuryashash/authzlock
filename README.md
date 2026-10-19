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
| Nemotron agent that *writes* the seeder, requests and tests and repairs them | **Not built.** Needs a Token Factory API key |
| Running probes inside Token Factory Sandboxes (forks for base/head/shards) | **Not built.** Needs Sandboxes access. Runs on local Postgres for now |
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

## Known limitations of this prototype

- The seeder, parameter mapping (`manifest.json` → `param_hints`) and test patterns are hand-written for this template. Generalising them is the agent's job.
- Probes run in-process with Starlette's TestClient, one process per SHA. The production design runs the app as a separate process and OS user inside a sandbox.
- Single-tenant, per-user ownership only. Time-based and sharing rules are out of scope.
