import uuid
from app import crud
from app.models import UserCreate

CANARY = "cnry-pr-mut-users-no-role"

def test_get_users_requires_superuser(client, normal_user_token_headers, db):
    # Create a victim user whose full_name contains the CANARY
    victim_email = f"{uuid.uuid4()}@example.com"
    victim_in = UserCreate(email=victim_email, password="password", full_name=CANARY)
    victim = crud.create_user(session=db, user_create=victim_in)

    # Attempt to list users as a normal user (non-superuser)
    response = client.get(f"/api/v1/users/", headers=normal_user_token_headers)
    # Base behavior: endpoint protected -> 403 Forbidden
    assert response.status_code == 403, (
        f"Expected 403 for non-superuser accessing {response.request.url}, "
        f"got {response.status_code}. This indicates missing superuser dependency."
    )
    # Additionally ensure the CANARY is not leaked in any error payload
    assert CANARY not in response.text