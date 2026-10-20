## authz.lock: **❌ FAIL**

**Count side channel:** <code>GET /items/ \| user_a \| - \| base</code> 7 → 14; <code>GET /items/ \| user_b \| - \| base</code> 3 → 14

### Regression test: proven (2 prove runs; passes on base, fails on this PR)

<details><summary>tests/authz/test_regression.py (written by Nemotron, checked by JUnit)</summary>

~~~~python
import pytest
from tests.utils.user import create_random_user, authentication_token_from_email
from app.models import ItemCreate

CANARY = "cnry-pr-count-leak"

def test_count_side_channel_leak(client, db):
    # Create two normal users
    user_a = create_random_user(db)
    user_b = create_random_user(db)

    # Get tokens
    headers_a = authentication_token_from_email(client=client, email=user_a.email, db=db)
    headers_b = authentication_token_from_email(client=client, email=user_b.email, db=db)

    # User A creates 5 items, one containing the canary in title
    for i in range(5):
        title = f"item{i}" + (CANARY if i == 0 else "")
        item_in = ItemCreate(title=title, description=f"desc{i}", price=i*10.0)
        response = client.post("/api/v1/items/", json=item_in.model_dump(), headers=headers_a)
        assert response.status_code == 200, f"Failed to create item for user_a: {response.text}"

    # User B creates 3 items without canary
    for i in range(3):
        item_in = ItemCreate(title=f"bitem{i}", description=f"bdesc{i}", price=i*5.0)
        response = client.post("/api/v1/items/", json=item_in.model_dump(), headers=headers_b)
        assert response.status_code == 200, f"Failed to create item for user_b: {response.text}"

    # Now request items as user B
    resp = client.get("/api/v1/items/", headers=headers_b)
    assert resp.status_code == 200
    data = resp.json()
    # On base, count should be only user B's items (3)
    expected_count = 3
    assert data["count"] == expected_count, f"Expected count {expected_count} but got {data['count']}"
    # Ensure canary not present in any returned item
    for item in data["data"]:
        assert CANARY not in item["title"], f"Canary leaked in item title: {item['title']}"
        assert CANARY not in item["description"], f"Canary leaked in item description: {item['description']}"
~~~~

</details>

### Root cause (Nemotron Ultra, advisory; does not affect the verdict)

The diff removes the 'where(Item.owner_id == current_user.id)' filter from the count query (line -3 to -5 replaced by line +3), causing 'count_statement' to return the total number of all items instead of only the current user's items. This widens the authorization scope: both 'user_a' and 'user_b' now receive a global item count, leaking information about other users' data. Restore the ownership filter, e.g., 'select(func.count()).select_from(Item).where(Item.owner_id == current_user.id)', so the count remains scoped to the authenticated user.

