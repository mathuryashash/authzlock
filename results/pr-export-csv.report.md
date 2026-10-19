## authz.lock — pr-export-csv — AI-written CSV export endpoint that forgets the owner filter

**Verdict: ❌ FAIL**

Probes: base 603 (99.1s) · head 612 (99.0s) · coverage 21/23 operations

**New operations** (no baseline; judged by invariants): `GET /items/export`

### Invariant violations introduced by this PR

| Rule | Operation | Who | Example evidence |
|---|---|---|---|
| I1 read-isolation | `GET /items/export` | user_a, user_b | user_a received data owned by inactive, superuser, user_b |

### Maintainer decision

Only a maintainer knows whether this was intended. In the GitHub Action (not built in this prototype) the check stays red until a maintainer replies `/authz accept <decision-id>`, which updates authz.lock. A runnable regression test for these findings is generated separately (`<scenario>.test_authz_regressions.py`) and proven to pass on base and fail on this PR.
