## authz.lock: **❌ FAIL**

**New operations** (judged by invariants): <code>GET /items/export</code>

| Rule | Operation | Who | Example |
|---|---|---|---|
| I1 read-isolation | <code>GET /items/export</code> | user_a, user_b | user_a received data owned by inactive, superuser, user_b |

### Regression test: proven (2 prove runs; passes on base, fails on this PR)

<details><summary>tests/authz/test_regression.py (written by Nemotron, checked by JUnit)</summary>

~~~~python
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.utils.user import authentication_token_from_email, create_random_user
from app import crud
from app.models import Item, ItemCreate
from app.core.config import settings

CANARY = "cnry-pr-export-csv"


def test_export_items_isolation(client: TestClient, db: Session, normal_user_token_headers: dict[str, str]):
    # User A from fixture
    user_a_headers = normal_user_token_headers
    # Random user B
    user_b = create_random_user(db)
    user_b_headers = authentication_token_from_email(
        client=client, email=user_b.email, db=db
    )

    # Each user creates an item with the canary in title
    item_in_a = ItemCreate(title=f"{CANARY}-a", description="desc-a")
    item_in_b = ItemCreate(title=f"{CANARY}-b", description="desc-b")

    def create_item(headers, item_in):
        resp = client.post(
            f"{settings.API_V1_STR}/items/",
            json=item_in.model_dump(),
            headers=headers,
        )
        assert resp.status_code == 200, f"create item failed: {resp.text}"
        return resp.json()

    item_a = create_item(user_a_headers, item_in_a)
    item_b = create_item(user_b_headers, item_in_b)

    # Try to access export endpoint
    resp = client.get(f"{settings.API_V1_STR}/items/export", headers=user_a_headers)
    # If the endpoint does not exist (or any non-200), test passes on base
    if resp.status_code != 200:
        return

    # Head branch: endpoint exists
    assert resp.status_code == 200, f"export failed: {resp.text}"
    csv_text = resp.text
    # User A should see their own item
    assert f"{CANARY}-a" in csv_text, f"User A did not see own item. CSV: {csv_text}"
    # Isolation violation: user A must NOT see user B's canary
    assert f"{CANARY}-b" not in csv_text, f"User A saw user B's item. CSV: {csv_text}"
~~~~

</details>

### Root cause (Nemotron Ultra, advisory; does not affect the verdict)

The new 'export_items' endpoint (lines 48-57) queries **all** 'Item' rows via 'session.exec(select(Item).order_by(...)).all()' without filtering by 'current_user', so any authenticated caller can download every item's data via 'GET /items/export'. This widens the attack surface for **I1 read-isolation** by bypassing the per-object authorization that protects the regular list and detail routes, constituting an **Insecure Direct Object Reference** / **Broken Object Level Authorization** flaw (CWE‑639, API1:2023). The fix is to scope the query to the current user's authorized items (e.g., 'select(Item).where(Item.owner_id == current_user.id)') or enforce the same policy check used in 'read_items'.

> CWE - CWE-639: Authorization Bypass Through User-Controlled Key (4.20): https://cwe.mitre.org/data/definitions/639.html
> API1:2023 Broken Object Level Authorization - OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization
> Insecure Direct Object Reference Prevention - OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
