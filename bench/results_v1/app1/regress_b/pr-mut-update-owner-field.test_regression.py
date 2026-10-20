import uuid

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from tests.utils.user import create_random_user, authentication_token_from_email
from tests.utils.item import create_random_item


def test_put_item_owner_cannot_change_owner_id(
    client: TestClient, db: Session
) -> None:
    """
    Regression test for PR-mut-update-owner-field:
    PUT /items/{id} should not allow changing the owner_id via update.
    The CANARY is embedded in the item title.
    """
    # Create two distinct users
    user_a = create_random_user(db)
    user_b = create_random_user(db)
    assert user_a.id != user_b.id

    # Get headers for each user
    headers_a = authentication_token_from_email(
        client=client, email=user_a.email, db=db
    )
    headers_b = authentication_token_from_email(
        client=client, email=user_b.email, db=db
    )

    # User A creates an item with the canary in the title
    caesar = "cnry-pr-mut-update-owner-field"
    item_data = {
        "title": caesar,
        "description": "owned by user A",
    }
    resp = client.post(
        f"{settings.API_V1_STR}/items/",
        headers=headers_a,
        json=item_data,
    )
    assert resp.status_code == 200
    item = resp.json()
    item_id = item["id"]
    assert item["title"] == caesar
    assert str(item["owner_id"]) == str(user_a.id)

    # User A (owner) attempts to update the item, trying to change owner_id to user B
    update_payload = {"owner_id": str(user_b.id)}
    resp = client.put(
        f"{settings.API_V1_STR}/items/{item_id}",
        headers=headers_a,
        json=update_payload,
    )
    # We do not assert on the response code because:
    #   - On base: extra field -> 422 (unprocessable entity) or 200 with ignored field.
    #   - On head: field allowed -> 200 (and changes ownership, which is the bug)
    # Instead, we check the state after the update attempt.

    # Retrieve the item to see if the owner_id changed
    resp_get = client.get(
        f"{settings.API_V1_STR}/items/{item_id}",
        headers=headers_a,
    )
    assert resp_get.status_code == 200
    updated = resp_get.json()
    # The title should remain the same (canary)
    assert updated["title"] == caesar, "Item title should not change"
    # The owner_id must still be user_a's id. If it changed to user_b's id, then the regression is present.
    assert str(updated["owner_id"]) == str(user_a.id), (
        f"Owner ID changed from {user_a.id} to {updated['owner_id']} after update by owner. "
        f"This indicates the write-isolation regression allowing ownership transfer."
    )