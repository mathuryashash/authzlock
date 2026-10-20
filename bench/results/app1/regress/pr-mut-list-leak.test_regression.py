import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from tests.utils.user import authentication_token_from_email, create_random_user
from tests.utils.utils import random_lower_string


def test_user_a_cannot_see_user_b_items_canary_leak(
    client: TestClient, db: Session
) -> None:
    # Create two distinct users
    user_a = create_random_user(db)
    user_b = create_random_user(db)
    # Ensure they are different
    assert user_a.id != user_b.id

    # Obtain headers for each user
    headers_a = authentication_token_from_email(
        client=client, email=user_a.email, db=db
    )
    headers_b = authentication_token_from_email(
        client=client, email=user_b.email, db=db
    )

    # Define the canary string
    canary = "cnry-pr-mut-list-leak"

    # User A creates an item containing the canary in title
    item_a_in = {
        "title": f"{canary}_A",
        "description": "user a item"
    }
    resp_a = client.post(
        f"{settings.API_V1_STR}/items/",
        headers=headers_a,
        json=item_a_in,
    )
    assert resp_a.status_code == 200, f"User A item creation failed: {resp_a.text}"
    item_a = resp_a.json()

    # User B creates an item without the canary (different title)
    item_b_in = {
        "title": random_lower_string(),
        "description": "user b item"
    }
    resp_b = client.post(
        f"{settings.API_V1_STR}/items/",
        headers=headers_b,
        json=item_b_in,
    )
    assert resp_b.status_code == 200, f"User B item creation failed: {resp_b.text}"
    item_b = resp_b.json()

    # Now user A requests the list of items
    list_resp = client.get(
        f"{settings.API_V1_STR}/items/",
        headers=headers_a,
    )
    assert list_resp.status_code == 200, f"List fetch failed: {list_resp.text}"
    data = list_resp.json()
    # Assuming the response format is {"data": [...]} as seen in existing test_read_items
    items = data.get("data", data)  # fallback if format differs

    # User A should only see their own item due to owner filter.
    # If the filter is missing (regression), they will see both items.
    # Assert that exactly one item is returned (their own).
    assert len(items) == 1, f"Expected 1 item for user A, got {len(items)}: {[i.get('title') for i in items]}"
    # Additionally, ensure the canary is in the returned item's title
    titles = [i.get("title") for i in items if isinstance(i, dict)]
    assert any(canary in t for t in titles), f"Canary not found in user A's item: {titles}"