## authz.lock: **❌ FAIL**

| Rule | Operation | Who | Example |
|---|---|---|---|
| I1 read-isolation | <code>GET /items/{id}</code> | user_a → user_b, user_a → superuser, user_b → user_a, user_b → superuser | user_a received data owned by user_b |

### Regression test: proven (2 prove runs; passes on base, fails on this PR)

<details><summary>tests/authz/test_regression.py (written by Nemotron, checked by JUnit)</summary>

~~~~python
import uuid

from tests.utils.user import create_random_user, authentication_token_from_email

CANARY = "cnry-pr-idor-refactor"


def test_item_read_isolation_regression(client, db):
    # create two normal users
    user_a = create_random_user(db)
    headers_a = authentication_token_from_email(
        client=client, email=user_a.email, db=db
    )
    user_b = create_random_user(db)
    headers_b = authentication_token_from_email(
        client=client, email=user_b.email, db=db
    )

    # user_a creates an item with the canary in description
    item_data = {
        "title": "private item",
        "description": CANARY,
    }
    resp = client.post("/api/v1/items/", json=item_data, headers=headers_a)
    assert resp.status_code == 200, resp.text
    item_id = resp.json()["id"]

    # user_b tries to read the item
    resp = client.get(f"/api/v1/items/{item_id}", headers=headers_b)
    # In the base version this should be forbidden (403)
    # After the regression it becomes allowed (200) and leaks the canary
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.json()}"
~~~~

</details>

### Root cause (Nemotron Ultra, advisory; does not affect the verdict)

The diff removes the ownership check from 'read_item' (old lines 55‑59: 'if not current_user.is_superuser and (item.owner_id != current_user.id): raise HTTPException(403)'). The new helper '_get_item_or_404' (lines 48‑52) only validates existence, so 'read_item' now returns any item by ID without verifying the caller owns it or is a superuser. This widens access to all users, violating I1 read‑isolation (CWE‑639, API1:2023). Fix: re‑add the permission check after '_get_item_or_404' (or inside it) before returning the item.

> CWE - CWE-639: Authorization Bypass Through User-Controlled Key (4.20): https://cwe.mitre.org/data/definitions/639.html
> API1:2023 Broken Object Level Authorization - OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization
> Insecure Direct Object Reference Prevention - OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
