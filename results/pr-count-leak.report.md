## authz.lock — pr-count-leak — 'Simplified' count query leaks the total item count to normal users

**Verdict: ❌ FAIL**

Probes: base 603 (99.1s) · head 603 (114.5s) · coverage 20/22 operations

### Access widened (lockfile diff)

| Cell | Base | Head |
|---|---|---|
| `GET /items/ | user_a | - | base` | ALLOW 200 leaks=['self'] db=- count=7 | ALLOW 200 leaks=['self'] db=- count=14 |
| `GET /items/ | user_b | - | base` | ALLOW 200 leaks=['self'] db=- count=3 | ALLOW 200 leaks=['self'] db=- count=14 |

### Maintainer decision

Only a maintainer knows whether this was intended. In the GitHub Action (not built in this prototype) the check stays red until a maintainer replies `/authz accept <decision-id>`, which updates authz.lock. A runnable regression test for these findings is generated separately (`<scenario>.test_authz_regressions.py`) and proven to pass on base and fail on this PR.
