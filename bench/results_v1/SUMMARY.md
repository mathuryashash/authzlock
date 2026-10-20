# Mutation benchmark, probe v1 (foreign-reference variant)

Probe v0 = before commit ed00a03; v1 = with it. Every PR is probed on its own fresh seed DB and diffed against a base
lock built by the same probe version (`base.lock.json` here). Windows laptop, Postgres 16 in Docker, 2 PRs in parallel.

| Set | v0 (before) | v1 (after) |
|---|---|---|
| Original breaking mutations | 9/11 | **11/11** |
| Held-out breaking mutations (written + committed in a8feeb6 before v1 existed) | 1/4 (v0 run: `bench/results_preheldout`) | **4/4** |
| Benign mutations, false positives | 0/4 | **0/4** |

Base locks: app1 603 cells, v1 adds 0 cells and changes 0 (the template has no optional `*_id` inputs). app2 639 -> 693
cells: +54 new `foreign_ref` cells (`POST /todos`, `PUT /todos/{todo_id}` with another user's `categories_ids`), all DENY
on base; 0 of the 639 existing cells changed. Both bases: 0 violations, harness valid.

The two v0 misses (`pr-mut-swap-user-source`, `pr-mut-foreign-category-link`) were invisible because v0 never sent
optional query params and always sent `categories_ids: []`. v1 sends the victim's seeded id in every query param / JSON
field named `<x>_id`/`<x>_ids` whose `<x>` the manifest knows (param hint, owned table, user table, owner column).

Time per PR (wall, probe + diff): app1 64 s (603-639 probes), app2 103 s (693-702 probes). Probing uses no LLM ($0).

Regression proofs for the 6 newly detected FAILs (Nemotron Super agent writes the test, `--runner sandbox` proves it in
Nebius Sandboxes, `proof.py` decides): **6/6 proven**. Two needed a second agent run (first runs: a test-collection
error, and a test that omitted the required `categories_ids` field; both rejected by `proof.py`). LLM spend
$0.437 (133 calls), i.e. $0.073 per FAIL PR including the failed attempts. Benign PRs: no model call.
