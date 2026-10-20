import pytest
from app import crud
from app.models import ItemCreate
from tests.utils.user import authentication_token_from_email
from tests.utils.utils import random_lower_string

CANARY = "cnry-pr-mut-superuser-inverted"

def test_superuser_sees_all_items_including_other_users(
    client,
    db,
    normal_user_token_headers: dict[str, str],
    superuser_token_headers: dict[str, str],
) -> None:
    # Create a normal user item with the canary in the title
    # Get the normal user from token headers (we can fetch user via email)
    from app.core.config import settings
    email = settings.EMAIL_TEST_USER
    # authentication_token_from_email logs in and returns headers; we need user object.
    # Instead, we can create a user via helper.
    from tests.utils.user import create_random_user
    normal_user = create_random_user(db)
    assert normal_user.id is not None
    item_in = ItemCreate(
        title=f"{CANARY} {random_lower_string()}",
        description=random_lower_string(),
    )
    item = crud.create_item(session=db, item_in=item_in, owner_id=normal_user.id)

    # Login as superuser (fixture provides headers)
    response = client.get(
        f"/api/v1/items/",
        headers=superuser_token_headers,
    )
    assert response.status_code == 200
    data = response.json()
    # Assuming response format: {"data": [...], ...} as seen in test_read_items
    items = data.get("data") if isinstance(data, dict) else data
    # Find item with canary in title
    found = any(CANARY in it.get("title", "") for it in items)
    assert found, f"Superuser did not see item with canary '{CANARY}'"