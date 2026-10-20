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