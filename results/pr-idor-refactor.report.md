## authz.lock — pr-idor-refactor — Refactor moves item lookup to a helper and silently drops the ownership check on GET /items/{id}

**Verdict: ❌ FAIL**

Probes: base 603 (99.1s) · head 603 (119.7s) · coverage 20/22 operations

### Invariant violations introduced by this PR

| Rule | Operation | Who | Example evidence |
|---|---|---|---|
| I1 read-isolation | `GET /items/{id}` | user_a → user_b, user_a → superuser, user_b → user_a, user_b → superuser | user_a received data owned by user_b |

### Access widened (lockfile diff)

| Cell | Base | Head |
|---|---|---|
| `GET /items/{id} | user_a | superuser | base` | DENY 403 leaks=- db=- count=None | ALLOW 200 leaks=['superuser'] db=- count=None |
| `GET /items/{id} | user_a | user_b | base` | DENY 403 leaks=- db=- count=None | ALLOW 200 leaks=['user_b'] db=- count=None |
| `GET /items/{id} | user_b | superuser | base` | DENY 403 leaks=- db=- count=None | ALLOW 200 leaks=['superuser'] db=- count=None |
| `GET /items/{id} | user_b | user_a | base` | DENY 403 leaks=- db=- count=None | ALLOW 200 leaks=['user_a'] db=- count=None |

### Maintainer decision

Only a maintainer knows whether this was intended. In the GitHub Action (not built in this prototype) the check stays red until a maintainer replies `/authz accept <decision-id>`, which updates authz.lock. A runnable regression test for these findings is generated separately (`<scenario>.test_authz_regressions.py`) and proven to pass on base and fail on this PR.
