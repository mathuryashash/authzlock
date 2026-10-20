import pytest
from fastapi.testclient import TestClient

CANARY = "cnry-pr-mass-assign"

def test_patch_users_me_mass_assignment_is_superuser(client: TestClient, normal_user_token_headers: dict[str, str]):
    # Set victim's full_name to include CANARY via allowed field
    resp = client.patch(
        "/api/v1/users/me",
        json={"full_name": CANARY},
        headers=normal_user_token_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["full_name"] == CANARY

    # Attempt to escalate privileges via mass assignment of is_superuser
    resp = client.patch(
        "/api/v1/users/me",
        json={"is_superuser": True, "full_name": CANARY},  # keep CANARY to see it
        headers=normal_user_token_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    # CANARY should still be present in full_name
    assert data["full_name"] == CANARY
    # The is_superuser flag must remain False (mass assignment should not succeed)
    assert data.get("is_superuser") is False, "Mass assignment allowed setting is_superuser"