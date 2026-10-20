# App #2 (eladgunders/fastapi-todos @ c059889): what a human wrote, what the agent wrote

**Edits to agent-written artifacts: 0.** The `manifest.json` and `seeder.py` used for every app-#2 lock, scenario and
regression proof are the onboarding agent's run-5 output, copied byte-for-byte to `results/app2/onboard_run5/` and
passed to `run_scenarios.py` unchanged. The regression tests in `regress_sandbox/` are also agent-written.

Runs 1-4 produced artifacts that were *not* used. They are kept as evidence of what failed. Each failure led to an engine
fix (with a test), never to a hand-patch of the artifact:

| Run | Outcome | Engine change it caused |
|---|---|---|
| 1 | 30 turns, max_turns. The seeder passed a dict to `UserManager.create` and lost `is_superuser`/`is_active`. The real error was buried under asyncio shutdown tracebacks | `root_error()`: the worker failure starts with the root exception. Seeder gate: identity flags are read back from the seed DB and must match the manifest |
| 2 | Harness valid, 17/20, 0 violations. Then a final rewrite set `ignored_columns: {}` before done | `write_file` validates the manifest and seeder immediately and returns INVALID to the agent |
| 3 | 40 turns. The async seeder left the app's global engine bound to a closed event loop, so every login returned 500 | The seeder runs in its own process (`probe_lib.run_seeder`) |
| 4 | Done, harness valid, 16/20. A final unverified manifest rewrite dropped the `app` section | The last artifacts that locked green are kept, and later rewrites are rolled back. Prompt: seed every owner-scoped table |
| 5 | **Used.** Final lock: harness valid, 17/20, 0 violations. Reported "never green" because of a parser bug | `green()` uses a regex on the tail-truncated output |

After run 5, the agent's manifest left `"shared"` out of `targets`, so the default-category PR was never probed (PASS).
I did not add it to the manifest. Instead the engine now always probes NULL-owner rows when the seed DB has them
(`probe_lib.effective_targets`). That is an engine rule, not a policy edit.

## Human-written inputs (infra, not policy; like `setup.sh` for app #1)

- `apps/todos/profile.json`: how to boot/migrate/test the app (cwd, PYTHONPATH, DB env var names, sandbox image and pip pins).
  Pins `bcrypt==4.0.1` (passlib), `setuptools<70`, `anyio==3.7.1` (starlette 0.20 TestClient) and the pytest plugins
  the app's own tests need.
- `apps/todos/app.env`: non-secret dev settings (generated JWT secret, local SMTP); gitignored.
- `apps/todos/scenarios/*.patch`: the 3 planted PRs (the "attacker"/benign authors). These are deliberately human.
- Scenario expectations (FAIL/FAIL/PASS) in `profile.json`, used only to score verdicts.
