import pytest
from httpx import AsyncClient
from tests.conftest_utils import get_tests_data

CANARY = "cnry-pr-todo-get-by-id"

@pytest.mark.asyncio
async def test_todo_get_by_id_isolation(client: AsyncClient):
    # Get token for first user (user_a)
    tests_data = get_tests_data()
    login_data_a = {
        'username': tests_data['users'][0]['email'],
        'password': tests_data['users'][0]['password'],
    }
    res_a = await client.post('/api/v1/auth/login', data=login_data_a)
    assert res_a.status_code == 200
    token_a = res_a.json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}

    # Get token for second user (user_b)
    login_data_b = {
        'username': tests_data['users'][1]['email'],
        'password': tests_data['users'][1]['password'],
    }
    res_b = await client.post('/api/v1/auth/login', data=login_data_b)
    assert res_b.status_code == 200
    token_b = res_b.json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}

    # Create a todo for user_a with CANARY in title
    resp_create_a = await client.post(
        '/api/v1/todos/',
        json={'title': f'{CANARY} user_a todo', 'description': 'private'},
        headers=headers_a,
    )
    assert resp_create_a.status_code == 200
    todo_a = resp_create_a.json()
    todo_id_a = todo_a['id']

    # Create a todo for user_b with CANARY in title
    resp_create_b = await client.post(
        '/api/v1/todos/',
        json={'title': f'{CANARY} user_b todo', 'description': 'private'},
        headers=headers_b,
    )
    assert resp_create_b.status_code == 200
    todo_b = resp_create_b.json()
    todo_id_b = todo_b['id']

    # Attempt to fetch user_b's todo using user_a's token (should be forbidden)
    resp = await client.get(f'/api/v1/todos/{todo_id_b}', headers=headers_a)
    # Base branch: isolation works -> 403 Forbidden (or maybe 404)
    # We assert that the response is NOT successful and does not leak CANARY
    assert resp.status_code != 200, f"Expected non-200, got {resp.status_code}"
    # Additionally, ensure CANARY not in response body (if any)
    assert CANARY not in resp.text
