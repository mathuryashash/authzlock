import pytest
from httpx import AsyncClient
from app.core.config import get_config

pytestmark = pytest.mark.asyncio

config = get_config()
API_TODOS_PREFIX = f'{config.API_V1_STR}/todos'
API_AUTH_LOGIN = f'{config.API_V1_STR}/auth/login'

async def test_put_todo_cross_user_forbidden_with_canary(client: AsyncClient):
    """
    Regression test for PR mut-update-skip-category-check.
    The PR removed the validation that categories belong to the user making the update.
    As a side effect, this might allow a user to update another user's todo by tampering with categories?
    However, the direct authorization check (ownership) should still prevent cross-user updates.
    This test ensures that a user cannot update another user's todo, and that the CANARY
    placed in the victim's todo content is not exposed.
    """
    # Helper to login and get token
    async def login(email: str, password: str = "test"):
        resp = await client.post(API_AUTH_LOGIN, data={'username': email, 'password': password})
        assert resp.status_code == 200, f"Login failed for {email}: {resp.status_code} {resp.text}"
        return resp.json()['access_token']

    # Log in as user_a (test1@test.com) to create a todo with the CANARY.
    token_a = await login('test1@test.com')
    headers_a = {'Authorization': f'Bearer {token_a}'}

    # Create a todo owned by user_a with the CANARY in its content.
    todo_payload = {
        "content": "cnry-pr-mut-update-skip-category-check",
        "priority_id": 1,
        "category_ids": [1]  # Personal category (global)
    }
    create_resp = await client.post(
        API_TODOS_PREFIX,
        json=todo_payload,
        headers=headers_a
    )
    # Accept 200 or 201
    assert create_resp.status_code in (200, 201), f"Failed to create todo: {create_resp.status_code} {create_resp.text}"
    todo_id = create_resp.json()['id']

    # Verify the todo was created and contains the CANARY.
    get_resp = await client.get(f'{API_TODOS_PREFIX}/{todo_id}', headers=headers_a)
    assert get_resp.status_code == 200, f"Failed to fetch todo: {get_resp.status_code} {get_resp.text}"
    todo_data = get_resp.json()
    assert todo_data['content'] == "cnry-pr-mut-update-skip-category-check", "CANARY not set in created todo"

    # Log in as user_b (test2@test.com) who should NOT be able to update user_a's todo.
    token_b = await login('test2@test.com')
    headers_b = {'Authorization': f'Bearer {token_b}'}

    # Attempt to update the todo as user_b.
    update_payload = {
        "content": "should not be seen",
        "priority_id": 2,
        "category_ids": [2]  # Work category (global)
    }
    update_resp = await client.put(
        f'{API_TODOS_PREFIX}/{todo_id}',
        json=update_payload,
        headers=headers_b,
        follow_redirects=True  # Ensure we follow any redirects to get final status
    )

    # The update must be forbidden (403) because user_b is not the owner.
    assert update_resp.status_code == 403, (
        f"Expected 403 Forbidden when user_b updates user_a's todo, "
        f"got {update_resp.status_code}: {update_resp.text}"
    )

    # Additionally, verify that the todo still contains the CANARY and was not modified.
    get_resp_after = await client.get(f'{API_TODOS_PREFIX}/{todo_id}', headers=headers_a)
    assert get_resp_after.status_code == 200, f"Failed to refetch todo: {get_resp_after.status_code} {get_resp_after.text}"
    todo_data_after = get_resp_after.json()
    assert todo_data_after['content'] == "cnry-pr-mut-update-skip-category-check", (
        f"CANARY was altered! Expected 'cnry-pr-mut-update-skip-category-check', got '{todo_data_after['content']}'"
    )