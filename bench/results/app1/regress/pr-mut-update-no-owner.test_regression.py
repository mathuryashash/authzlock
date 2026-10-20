import uuid

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from tests.utils.user import create_random_user, authentication_token_from_email
from tests.utils.item import create_random_item

CANARY = "cnry-pr-mut-update-no-owner"


def test_update_item_owner_isolation(
    client: TestClient, db: Session, normal_user_token_headers: dict[str, str]
) -> None:
    # Owner: create a random user and get token
    owner_user = create_random_user(db)
    owner_token = authentication_token_from_email(
        client=client, email=owner_user.email, db=db
    )
    # Attacker: use the existing normal user from fixture
    attacker_token = normal_user_token_headers

    # Owner creates an item with CANARY in title
    item_in = {
        "title": f"{CANARY} original",
        "description": "owned item",
    }
    resp = client.post(
        f"{settings.API_V1_STR}/items/",
        headers=owner_token,
        json=item_in,
    )
    assert resp.status_code == 200
    item = resp.json()
    item_id = item["id"]
    assert CANARY in item["title"]

    # Attacker attempts to update the item (should be forbidden)
    update_data = {"title": "hacked", "description": "tampered"}
    resp = client.put(
        f"{settings.API_V1_STR}/items/{item_id}",
        headers=attacker_token,
        json=update_data,
    )
    # Base branch: expects 403
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"
    # Fetch item again as owner to ensure unchanged
    resp = client.get(
        f"{settings.API_V1_STR}/items/{item_id}",
        headers=owner_token,
    )
    assert resp.status_code == 200
    fetched = resp.json()
    # CANARY must still be present in title
    assert CANARY in fetched["title"], f"CANARY missing from title: {fetched['title']}"