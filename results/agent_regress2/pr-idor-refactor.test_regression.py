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