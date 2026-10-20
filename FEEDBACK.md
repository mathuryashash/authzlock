# Feedback log: Nebius Token Factory, AI Cloud, NVIDIA Nemotron

This is a running log of friction and wins, kept while building authz.lock for the Nebius x NVIDIA Global AI Hackathon. Each entry covers:
- what it was used for
- what worked
- what needs work
- time to hello world
- whether I would build with it again

## 2026-10-19: onboarding (before the hackathon starts)

- **Billing with an Indian card.** Indian cards appear to be declined at Token Factory billing. Other participants have reported the same thing on the forum/Discord. Indian cards need RBI e-mandate / AFA for recurring international charges, so a card that works elsewhere can still fail here. Because of this I have **no API key yet**, and for a hackathon that requires TF inference, this is the #1 blocker. Suggested fixes:
  - a promo code or credit grant that doesn't need a card;
  - a prepaid credit top-up instead of a recurring mandate;
  - a clear error message that says which card types are accepted.
- **Sandboxes beta is gated.** Access to Token Factory Sandboxes needs a request or waitlist, with no published turnaround time. I planned around this: Sandboxes is used only for test proofs on base/head checkpoints, with a go/no-go on Oct 22. Publishing an expected approval time, or granting hackathon participants access automatically, would let builders commit to it.
- **SDK Python pin.** The `contree-sdk` docs pin Python 3.12, while my target app needs Python 3.14. I'll have to run the SDK in its own venv.
- **Docs / OpenAI compatibility.** Not yet verified. The plan is to use the `openai` package with `base_url=https://api.tokenfactory.nebius.com/v1/`. Time to hello world: _pending key_.
- **Model IDs are case-sensitive and inconsistent:** `nvidia/nemotron-3-super-120b-a12b` is lowercase, while `nvidia/Nemotron-3-Ultra-550b-a55b` is mixed case. Third-party catalogs list both spellings. To be verified against `/v1/models` once there's a key.
- **Pricing source.** I could only find per-token prices for Super ($0.30/$0.90 per M) and Ultra ($1/$3 per M) on third-party aggregators. A machine-readable price list on `/v1/models` would make cost caps reliable.

## 2026-10-20: first real agent run (D2)

- **Used for:** Nemotron 3 Super (`nvidia/nemotron-3-super-120b-a12b`) as a tool-calling agent that reads a FastAPI app's OpenAPI + source and writes a seeder (Python) and a policy/param manifest (JSON).
- **What worked:** OpenAI SDK with `base_url` worked unchanged; `tool_choice="required"` was honoured on every turn (14/14 calls returned a tool call, 0 malformed JSON arguments). The agent produced a working seeder on the first try, using the app's own `crud`/models, and followed the "every value carries the canary" contract. Latency 2–5 s per turn at 10–16k prompt tokens. Whole onboarding: 14 calls, 147k prompt / 8k completion tokens, **$0.051** (at the placeholder prices), 2m17s.
- **Needs work:** (1) Usage objects don't report cached prompt tokens, and agent loops resend a growing history, so prompt caching visibility would matter a lot for cost. (2) Prices are still not machine-readable from the API, so the $ cap depends on numbers copied by hand. (3) The model did redundant work: after a green run it re-read the OpenAPI and rewrote the manifest twice before calling `done`. That's a prompt issue on my side, but a "stop when the tool says success" behaviour would cut ~30% of tokens.
- **Would build with it again:** yes; tool calling on Super is reliable enough that the D1 fallback to Ultra for the loop was not needed.


## 2026-10-20: regression-test agent (D3) and Ultra root cause

- **Used for:** Nemotron Super writes a pytest regression test per finding and repairs it against a fixed `prove` tool (base/head JUnit). Nemotron Ultra writes one root-cause paragraph per FAIL, using Tavily OWASP/CWE results as quoted data.
- **What worked:** On the IDOR PR, Super read the app's conftest/test utils, wrote an idiomatic test with the canary, and reached a valid proof (pass on base, AssertionError on head). It took 16 turns and 3 prove runs. The whole run (Super + Ultra) cost $0.032. Ultra named the exact dropped lines and cited CWE-639 and API1:2023 correctly.
- **Friction:** (1) Ultra returns its reasoning inline, so I strip everything before `</think>`. A documented reasoning on/off flag would avoid wasted output tokens. (2) The model tried `read_file` on a directory twice. A `list_dir` tool would be cheaper than the errors. (3) My own bug: I compared base and head app hashes, which made a correct proof show as "app source changed". Each side now checks its own before/after.

## 2026-10-20: all 4 FAIL PRs proven live; GitHub Action live

- **Result:** Super proved all four FAIL PRs (count-leak, export-csv, idor-refactor, mass-assign) in 2 prove runs each (9-15 turns). Ultra wrote a root cause per finding. Both benign PRs: no test, no model call. Whole run: 47 calls, $0.089.
- **Friction (Token Factory):** none new. Per-call latency stayed low enough that the run took ~8 min, mostly local pytest.
- **Friction (my CI, found only on the first real run):** (1) `setup.sh` was committed without the executable bit (Windows checkout). (2) The probe did `git checkout -B pr_<side>` and then `worktree add` of that same branch, which git refuses; now detached worktrees + `git apply`. (3) `run_worker` passed a relative venv python with `cwd=backend`. (4) `authz-comment` ran after a failed probe and errored on the missing artifact; it now runs only on a successful probe. Each fix has a test.

## 2026-10-20: Sandboxes (ConTree) as the regression-proof runner

- **Used for:** running the agent-written regression tests on base and head of each PR, in disposable VMs with no secrets and no network (`sandbox_run.py --runner sandbox`). One snapshot per (app, base SHA) with Postgres + deps.
- **What worked:** the immutable image model fits proofs perfectly: build once with `disposable=False`, tag it, then every proof is a disposable fork. `files=` upload of a `git archive` tar made "committed tree only" trivial. 4/4 proofs matched local exactly; with 8 VMs in parallel the whole set took 12 s vs 45 s local. Python 3.14 image worked (the SDK itself runs fine on 3.13, despite the docs' 3.12 pin). Time to hello world after activation: ~15 min.
- **Friction:**
  1. **403 until email activation.** The key and project worked for inference but every Sandboxes call returned 403 until the beta activation email arrived. The 403 body didn't say "beta not enabled for this project"; a specific error would save a support round trip.
  2. **Transient 500s.** On `POST /instances` and on `GET /operations/{id}` polling (4 seen in ~40 ops). The SDK retries 429/timeouts but not 5xx, and a 500 while *polling* makes the SDK cancel an operation that was fine ("Cancelled by user" in the record). I added bounded backoff on 5xx; polling 5xx should be retried inside the SDK and never cancel.
  3. **Immutable-run model surprise.** Coming from "a sandbox is a box you exec into", it took a re-read to learn that every `run()` is fresh compute and nothing persists unless `disposable=False` returns a new image. Background services (Postgres) must start in the same shell command as the test. Clear in the docs once found; worth a one-line callout in the quickstart.
  4. **Network egress is open by default** and `networking.enabled=false` is documented only on the security page, not exposed by contree-sdk 0.3.6 (`run()` has no parameter). I inject it into the spawn body. For an "isolated environment for agents", default-off or at least an SDK flag would be safer.
  5. **No SysV shared memory in the guest** (`shmget` ENOSYS): stock Postgres `initdb` fails. Worked around with a 20-line LD_PRELOAD shim + `shared_memory_type=mmap`. Also `python:*-slim` has no UTF-8 locale, so `initdb` picks SQL_ASCII unless `-E UTF8 --locale=C.UTF-8`. A documented "databases in sandboxes" recipe would help.
  6. One cold-run proof took 196 s vs ~17 s for its siblings, no error surfaced; not reproduced in 3 later runs.
- **Would build with it again:** yes. Forkable snapshots are the right primitive for base/head proofs.

## 2026-10-20: app #2 (fastapi-todos) onboarded by Nemotron; regression proofs live in Sandboxes

- **Result:** Super wrote the manifest and seeder for a Python 3.9, async-SQLAlchemy, fastapi-users app with 0 human edits. Base lock 17/20, 2/2 planted FAIL PRs caught, benign PASS. The live regress loop proved both FAIL tests inside Sandboxes (python:3.9-slim snapshot). D5 spend: $1.14.
- **Friction (model):** (1) It took 5 onboarding runs. Super often rewrote a working manifest one last time before `done` and broke it, so the engine now keeps the last green pair. (2) Async seeders leaked the app's engine onto a closed event loop, so seeding now runs in its own process. (3) It guessed paths (`tests/conftest.py` instead of `todos/tests/conftest.py`) and dropped the `/api/v1` prefix until both were put in the first message. A `list_dir` tool would still help.
- **Friction (Sandboxes):** (1) `images.use('python:3.9-slim')` returns 404 until the image is imported. `images.pull` resolves tags only, `import_from` is the call that works, and the names are easy to confuse. (2) Transient 500s are still common (about 1 in 5 spawns), all absorbed by the retry.
## 2026-10-20: held-out benchmark, 6 more proofs in Sandboxes

- **Result:** Super wrote regression tests for the 6 PRs the new foreign-reference probe caught, and all 6 were proven in Sandboxes. Total $0.437 over 133 calls. 4 tests were proven on the first agent run. The other 2 needed a second run: one first attempt failed test collection, and the other left out a required body field (`categories_ids`), so its test failed on base too. `proof.py` rejected both; it never accepted a wrong test.
- **Friction (model):** the costly failures were runs that spent all 24 turns rewriting a test that could not be collected. Showing the pytest collection error earlier would help, and so would a model that reads the 422 body before rewriting.
- **Friction (Sandboxes):** transient 500s on spawn are still about 1 in 5. All of them were absorbed by the retry.
