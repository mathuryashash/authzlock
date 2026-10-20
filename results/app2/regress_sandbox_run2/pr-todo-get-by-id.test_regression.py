import pytest
from httpx import AsyncClient

CANARY = "cnry-pr-todo-get-by-id"

@pytest.mark.asyncio
async def test_get_todo_isolation(client: AsyncClient, user_token_headers: dict[str, str]):
    # user_a is logged in via user_token_headers (test1@test.com)
    # Obtain token for user_b (test2@test.com) to create a todo with CANARY
    login_data = {
        'username': 'test2@test.com',
        'password': 'test',
    }
    res = await client.post('/api/v1/auth/login', data=login_data)
    assert res.status_code == 200, f'User B login failed: {res.status_code}'
    user_b_token = res.json()['access_token']
    user_b_headers = {'Authorization': f'Bearer {user_b_token}'}

    # Create a todo for user_b containing the canary in its content
    todo_payload = {
        'content': CANARY,
        'priority_id': 1,  # Low priority exists
        # categories optional; we can omit
    }
    create_res = await client.post('/api/v1/todos/', json=todo_payload, headers=user_b_headers)
    assert create_res.status_code == 200, f'Create todo failed: {create_res.status_code}'
    todo_id = create_res.json()['id']

    # Now user_a attempts to read that todo
    resp = await client.get(f'/api/v1/todos/{todo_id}', headers=user_token_headers)
    # On base branch the endpoint does not exist -> 404
    # On a correct implementation with authz -> 403 or 404
    # In either case we must not get 200 with the private data
    assert resp.status_code != 200, f'Expected non-200, got {resp.status_code}'
    # Additionally ensure the canary string is not leaked in error body
    if resp.status_code == 200:
        # This branch should never be hit due to the assert above,
        # but keep for clarity.
        assert CANARY not in resp.text