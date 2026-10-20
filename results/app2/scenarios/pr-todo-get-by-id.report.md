## authz.lock — pr-todo-get-by-id — New GET /todos/{todo_id} endpoint looks the todo up by id only (no created_by_id filter)

**Verdict: ❌ FAIL**

Probes: base 639 (106.0s) · head 684 (108.6s) · coverage 18/21 operations

**New operations** (no baseline; judged by invariants): `GET /todos/{todo_id}`

### Invariant violations introduced by this PR

| Rule | Operation | Who | Example evidence |
|---|---|---|---|
| I1 read-isolation | `GET /todos/{todo_id}` | user_a → user_b, user_a → superuser, user_b → user_a, user_b → superuser | user_a received data owned by user_b |

### Maintainer decision

Only a maintainer knows whether this was intended. In the GitHub Action (not built in this prototype) the check stays red until a maintainer replies `/authz accept <decision-id>`, which updates authz.lock. A runnable regression test for these findings is generated separately (`<scenario>.test_authz_regressions.py`) and proven to pass on base and fail on this PR.
