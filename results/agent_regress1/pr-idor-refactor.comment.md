## authz.lock: **❌ FAIL**

| Rule | Operation | Who | Example |
|---|---|---|---|
| I1 read-isolation | <code>GET /items/{id}</code> | user_a → user_b, user_a → superuser, user_b → user_a, user_b → superuser | user_a received data owned by user_b |

### Regression test: proven (3 prove runs; passes on base, fails on this PR)

<details><summary>tests/authz/test_regression.py (written by Nemotron, checked by JUnit)</summary>

~~~~python

~~~~

</details>

### Root cause (Nemotron Ultra, advisory; does not affect the verdict)

The refactor introduced '_get_item_or_404' (lines 47‑51) which only validates existence (404) but drops the ownership check that previously guarded 'read_item'. The original lines 58‑59 ('if not current_user.is_superuser and (item.owner_id != current_user.id): raise HTTPException(403,…)') are no longer executed, so any authenticated user can now read any item by ID — a classic IDOR / broken object-level authorization (OWASP API1:2023, CWE‑639). Fix: restore the authorization logic in 'read_item' after calling the helper, or add an 'owner_id'/'current_user' parameter to '_get_item_or_404' and enforce the 403 there.

> CWE - CWE-639: Authorization Bypass Through User-Controlled Key (4.20): https://cwe.mitre.org/data/definitions/639.html
> API1:2023 Broken Object Level Authorization - OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization
> Insecure Direct Object Reference Prevention - OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
