## authz.lock — same code, template's development .env vs production profile

**Verdict: ❌ FAIL**

Probes: base 603 (99.1s) · head 621 (127.5s) · coverage 21/23 operations

**New operations** (no baseline; judged by invariants): `POST /private/users/`

### Invariant violations introduced by this PR

| Rule | Operation | Who | Example evidence |
|---|---|---|---|
| I3 write-isolation | `POST /private/users/` | anonymous, anonymous (hostile body), user_a, user_a (hostile body), user_b, user_b (hostile body), inactive, inactive (hostile body), forged_sig, forged_sig (hostile body), expired, expired (hostile body), alg_none, alg_none (hostile body), deleted_user, deleted_user (hostile body) | anonymous created a new user account |
| I5 authn | `POST /private/users/` | anonymous, anonymous (hostile body), inactive, inactive (hostile body), forged_sig, forged_sig (hostile body), expired, expired (hostile body), alg_none, alg_none (hostile body), deleted_user, deleted_user (hostile body) | anonymous was allowed (HTTP 200) on a non-public operation |

### Maintainer decision

Only a maintainer knows whether this was intended. In the GitHub Action (not built in this prototype) the check stays red until a maintainer replies `/authz accept <decision-id>`, which updates authz.lock. A runnable regression test for these findings is generated separately (`<scenario>.test_authz_regressions.py`) and proven to pass on base and fail on this PR.
