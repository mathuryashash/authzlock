## authz.lock — pr-mass-assign — is_superuser / is_active added to the /users/me update schema

**Verdict: ❌ FAIL**

Probes: base 603 (99.1s) · head 603 (110.2s) · coverage 20/22 operations

### Invariant violations introduced by this PR

| Rule | Operation | Who | Example evidence |
|---|---|---|---|
| I4 privilege | `PATCH /users/me` | user_a (hostile body), user_b (hostile body) | user_a changed privilege columns ['is_superuser'] on a user row owned by self |

### Access widened (lockfile diff)

| Cell | Base | Head |
|---|---|---|
| `PATCH /users/me | user_a | - | hostile` | ALLOW 200 leaks=['self'] db=['update:user:self'] count=None | ALLOW 200 leaks=['self'] db=['update:user:self[priv:is_superuser]'] count=None |
| `PATCH /users/me | user_b | - | hostile` | ALLOW 200 leaks=['self'] db=['update:user:self'] count=None | ALLOW 200 leaks=['self'] db=['update:user:self[priv:is_superuser]'] count=None |

### Maintainer decision

Only a maintainer knows whether this was intended. In the GitHub Action (not built in this prototype) the check stays red until a maintainer replies `/authz accept <decision-id>`, which updates authz.lock. A runnable regression test for these findings is generated separately (`<scenario>.test_authz_regressions.py`) and proven to pass on base and fail on this PR.
