import uuid
from fastapi.testclient import TestClient
from sqlmodel import Session

from app import crud
from app.core.config import settings
from app.models import ItemCreate
from tests.utils.user import create_random_user, authentication_token_from_email

CANARY = "cnry-pr-mut-items-owner-param"


def test_owner_id_query_param_isolation(client: TestClient, db: Session) -> None:
    # Create two normal users
    user_a = create_random_user(db)
    user_b = create_random_user(db)

    # Get tokens for each
    headers_a = authentication_token_from_email(
        client=client, email=user_a.email, db=db
    )
    headers_b = authentication_token_from_email(
        client=client, email=user_b.email, db=db
    )

    # Create an item for user_b that contains the canary in title
    item_in = ItemCreate(title=f"{CANARY} title", description=f"{CANARY} desc")
    item_b = crud.create_item(session=db, item_in=item_in, owner_id=user_b.id)
    # No need to refresh; item_b has id

    # User A requests list of items, trying to bypass isolation via owner_id param
    # This should NOT return user_b's item on a correct implementation
    response = client.get(
        f"{settings.API_V1_STR}/items/?owner_id={user_b.id}",
        headers=headers_a,
    )
    assert response.status_code == 200
    data = response.json()
    # Ensure the canary does NOT appear in any returned item
    for item in data.get("data", []):
        assert CANARY not in item["title"]
        assert CANARY not in item["description"]
    # Also ensure total count does not include the canary item
    # (optional, but we can check that the count of items is not increased)
    # For safety, we also verify that user A cannot see the item by ID directly
    response_single = client.get(
        f"{settings.API_V1_STR}/items/{item_b.id}",
        headers=headers_a,
    )
    assert response_single.status_code == 403  # should be forbidden