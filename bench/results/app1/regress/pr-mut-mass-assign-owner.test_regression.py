import uuid
from fastapi.testclient import TestClient
from sqlmodel import Session

from app import crud
from app.core.config import settings
from app.models import UserCreate
from tests.utils.user import user_authentication_headers
from tests.utils.utils import random_email, random_lower_string

CANARY = "cnry-pr-mut-mass-assign-owner"


def test_owner_id_mass_assignment_isolation(
    client: TestClient, db: Session
) -> None:
    # Create attacker user
    email_a = random_email()
    password_a = random_lower_string()
    user_in_a = UserCreate(email=email_a, password=password_a)
    user_a = crud.create_user(session=db, user_create=user_in_a)
    headers_a = user_authentication_headers(
        client=client, email=email_a, password=password_a
    )

    # Create victim user
    email_b = random_email()
    password_b = random_lower_string()
    user_in_b = UserCreate(email=email_b, password=password_b)
    user_b = crud.create_user(session=db, user_create=user_in_b)
    victim_id = user_b.id

    # Attacker attempts to create an item setting owner_id to victim's id
    payload = {
        "title": CANARY,
        "description": "owned by victim",
        "owner_id": str(victim_id),
    }
    url = f"{settings.API_V1_STR}/items/"
    resp_create = client.post(url, headers=headers_a, json=payload)
    assert resp_create.status_code == 200, "Item creation should succeed"
    data = resp_create.json()
    item_id = data["id"]

    # Attacker tries to read the item they just created
    resp_get = client.get(f"{settings.API_V1_STR}/items/{item_id}", headers=headers_a)
    # On base branch, attacker owns the item (owner_id forced to attacker) -> 200
    # On PR branch, item belongs to victim -> attacker gets 403
    assert resp_get.status_code == 200, (
        "Attacker should be able to read the item they created "
        "(owner_id should be ignored on base, but honored on PR leading to isolation)"
    )
    # Additionally, ensure the canary is present in the returned title
    assert resp_get.json()["title"] == CANARY