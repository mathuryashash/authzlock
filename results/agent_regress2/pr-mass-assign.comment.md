## authz.lock: **❌ FAIL**

| Rule | Operation | Who | Example |
|---|---|---|---|
| I4 privilege | <code>PATCH /users/me</code> | user_a (hostile body), user_b (hostile body) | user_a changed privilege columns \['is_superuser'] on a user row owned by self |

### Regression test: proven (2 prove runs; passes on base, fails on this PR)

<details><summary>tests/authz/test_regression.py (written by Nemotron, checked by JUnit)</summary>

~~~~python
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
~~~~

</details>

### Root cause (Nemotron Ultra, advisory; does not affect the verdict)

The diff adds 'is_active: bool \| None = None' and 'is_superuser: bool \| None = None' to 'UserUpdateMe' (lines 44-45), which is the request model for 'PATCH /users/me'. This exposes critical authorization fields to self-service updates, letting any authenticated user toggle their own active status or grant themselves superuser privileges — a classic mass-assignment / privilege-escalation flaw (OWASP Mass Assignment Cheat Sheet; CWE-732). Remove those two fields from 'UserUpdateMe' (or gate them behind an admin-only endpoint) so users cannot modify their own role/state.

> Mass Assignment - OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
> API6:2019 - Mass Assignment - OWASP API Security Top 10: https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment
> CWE - CWE-732: Incorrect Permission Assignment for Critical Resource (4.20): https://cwe.mitre.org/data/definitions/732.html
