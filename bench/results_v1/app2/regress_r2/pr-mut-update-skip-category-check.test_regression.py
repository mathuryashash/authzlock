import pytest
from httpx import AsyncClient
from tests.conftest_utils import get_tests_data
from app.core.config import get_config

config = get_config()
API_TODOS_PREFIX = f'{config.API_V1_STR}/todos'
CANARY = "cnry-pr-mut-update-skip-category-check"


async def get_token_for_user(client: AsyncClient, index: int) -> dict[str, str]:
    """Return auth headers for the user at given index in tests_data."""
    tests_data = get_tests_data()
    user = tests_data['users'][index]
    login_data = {
        'username': user['email'],
        'password': user['password'],
    }
    res = await client.post(f'{config.API_V1_STR}/auth/login', data=login_data)
    access_token = res.json()['access_token']
    return {'Authorization': f'Bearer {access_token}'}


@pytest.mark.asyncio
async def test_update_todo_with_foreign_category_is_blocked(client: AsyncClient):
    """
    Regression test for PR mut-update-skip-category-check:
    A user must not be able to update their own todo with a category that belongs to another user.
    On base branch this should return 400 (categories are not valid).
    On the PR branch the validation is missing and the request may succeed (200).
    """
    # Use user 0 (index 0) as the actor
    headers = await get_token_for_user(client, 0)

    # Todo ID 1 belongs to user 0 (from seed data)
    todo_id = 1

    # Category ID 4 belongs to user 1 (Nintendo) – see tests_data.json
    foreign_category_id = 4

    # Prepare update payload with CANARY in content to detect if it persists
    update_payload = {
        'content': f'{CANARY} Learn the sicilian opening',
        'is_completed': True,
        'priority_id': 2,  # Medium priority exists
        'categories_ids': [1, foreign_category_id],  # mix of own (1) and foreign (4)
    }

    resp = await client.put(
        f'{API_TODOS_PREFIX}/{todo_id}',
        json=update_payload,
        headers=headers,
    )

    # On base branch, the validation should reject foreign categories -> 400
    # On the PR branch, the validation is removed -> may succeed (200)
    if resp.status_code == 200:
        # If we get 200, the validation is missing -> this is the regression we want to catch.
        # Fail the test to indicate regression.
        assert False, f"Regression detected: update succeeded with foreign category (status {resp.status_code})"
    else:
        # Otherwise we expect a client error (4xx) because the validation is present.
        assert resp.status_code >= 400, f"Expected 4xx, got {resp.status_code}"