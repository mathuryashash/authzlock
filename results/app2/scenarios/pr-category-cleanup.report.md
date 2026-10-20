## authz.lock — pr-category-cleanup — 'Let users clean up default categories': delete_category also allows rows with created_by_id NULL

**Verdict: ❌ FAIL**

Probes: base 639 (106.0s) · head 639 (102.3s) · coverage 17/20 operations

### Invariant violations introduced by this PR

| Rule | Operation | Who | Example evidence |
|---|---|---|---|
| I3 write-isolation | `DELETE /categories/{category_id}` | user_a → shared, user_b → shared | user_a deleted a category row owned by shared |

### Access widened (lockfile diff)

| Cell | Base | Head |
|---|---|---|
| `DELETE /categories/{category_id} | superuser | shared | base` | DENY 403 leaks=- db=- count=None | ALLOW 204 leaks=- db=['delete:category:shared'] count=None |
| `DELETE /categories/{category_id} | user_a | shared | base` | DENY 403 leaks=- db=- count=None | ALLOW 204 leaks=- db=['delete:category:shared'] count=None |
| `DELETE /categories/{category_id} | user_b | shared | base` | DENY 403 leaks=- db=- count=None | ALLOW 204 leaks=- db=['delete:category:shared'] count=None |

### Maintainer decision

Only a maintainer knows whether this was intended. In the GitHub Action (not built in this prototype) the check stays red until a maintainer replies `/authz accept <decision-id>`, which updates authz.lock. A runnable regression test for these findings is generated separately (`<scenario>.test_authz_regressions.py`) and proven to pass on base and fail on this PR.
