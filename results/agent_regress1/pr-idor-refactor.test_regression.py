import uuid
from app.core.config import settings

from tests.utils.user import authentication_token_from_email, create_random_user

CANARY = "cnry-pr-idor-refactor"


def test_item_read_isolation(client, db):
    # Path: /items/{id}
    # create two regular users
    user_a = create_random_user(db)
    user_b = create_random_user(db)

    # obtain tokens (passwords are random inside the helpers)
    headers_a = authentication_token_from_email(
        client=client, email=user_a.email, db=db
    )
    headers_b = authentication_token_from_email(
        client=client, email=user_b.email, db=db
    )

    # user_a creates an item whose title contains the canary string
    item_in = {
        "title": f"Item with {CANARY}",
        "description": "private item",
    }
    resp = client.post(
        f"{settings.API_V1_STR}/items/", json=item_in, headers=headers_a
    )
    assert resp.status_code == 200, f"Failed to create item: {resp.text}"
    item_data = resp.json()
    item_id = item_data["id"]
    # owner can see the canary
    assert CANARY in item_data["title"]

    # user_b attempts to read the item – should be forbidden
    resp = client.get(
        f"{settings.API_V1_STR}/items/{item_id}", headers=headers_b
    )
    # The regression would allow the read (200) and leak the canary.
    assert resp.status_code == 403, (
        f"Expected 403 Forbidden when user_b reads user_a's item, "
        f"got {resp.status_code}: {resp.text}"
    )
    # Ensure the canary is not present in the response body
    assert CANARY not in resp.text