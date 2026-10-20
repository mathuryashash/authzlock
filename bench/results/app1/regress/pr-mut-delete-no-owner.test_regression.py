import uuid

from app import crud
from app.models import UserCreate
from tests.utils.user import create_random_user, authentication_token_from_email
from tests.utils.item import create_random_item
from app.core.config import settings

CANARY = "cnry-pr-mut-delete-no-owner"


def test_delete_item_owner_isolation(client, db):
    # Owner user (user_a)
    owner_user = create_random_user(db)
    owner_headers = authentication_token_from_email(
        client=client, email=owner_user.email, db=db
    )
    # Attacker user (user_b) - normal user
    attacker_user = create_random_user(db)
    attacker_headers = authentication_token_from_email(
        client=client, email=attacker_user.email, db=db
    )

    # Create an item owned by owner_user, with CANARY in title
    item_in = {
        "title": f"{CANARY} owned item",
        "description": "some description",
    }
    # Use superuser? Actually we need to create item via owner. We can use owner headers to POST.
    resp = client.post(
        f"{settings.API_V1_STR}/items/",
        headers=owner_headers,
        json=item_in,
    )
    assert resp.status_code == 200
    item = resp.json()
    item_id = item["id"]

    # Verify attacker cannot delete item (should be 403 on base)
    del_resp = client.delete(
        f"{settings.API_V1_STR}/items/{item_id}",
        headers=attacker_headers,
    )
    # On base branch this should be 403; on PR branch missing check => 200
    assert del_resp.status_code == 403, f"Expected 403, got {del_resp.status_code}"
    # Ensure item still exists (optional)
    get_resp = client.get(
        f"{settings.API_V1_STR}/items/{item_id}",
        headers=owner_headers,
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["title"] == item_in["title"]