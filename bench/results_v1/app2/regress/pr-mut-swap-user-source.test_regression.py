import pytest
from httpx import AsyncClient

API_PREFIX = '/api/v1/todos'
CANARY = 'cnry-pr-mut-swap-user-source'


async def _login(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    from app.core.config import get_config
    config = get_config()
    resp = await client.post(f'{config.API_V1_STR}/auth/login', data={'username': email, 'password': password})
    assert resp.status_code == 200, f'Login failed: {resp.text}'
    token = resp.json()['access_token']
    return {'Authorization': f'Bearer {token}'}


@pytest.mark.asyncio
async def test_get_todos_user_id_isolation(client: AsyncClient):
    # attacker is test1@test.com (first user in seed data)
    attacker_email = 'test1@test.com'
    attacker_pass = 'test'
    # victim is test2@test.com (second user)
    victim_email = 'test2@test.com'
    victim_pass = 'test'

    # login as victim to create a private todo with CANARY
    victim_headers = await _login(client, victim_email, victim_pass)
    # create a todo
    todo_payload = {
        'content': f'Important task {CANARY}',
        'priority_id': 1,
        'categories_ids': [1]
    }
    resp_create = await client.post(API_PREFIX, headers=victim_headers, json=todo_payload)
    assert resp_create.status_code == 201, f'Create todo failed: {resp_create.text}'

    # login as attacker
    attacker_headers = await _login(client, attacker_email, attacker_pass)

    # request GET /todos with victim's user_id (we know victim id is 2 from seed data)
    victim_user_id = 2
    resp = await client.get(f'{API_PREFIX}?user_id={victim_user_id}', headers=attacker_headers)
    assert resp.status_code == 200, f'GET todos failed: {resp.text}'
    data = resp.json()
    # Ensure attacker does NOT see the victim's CANARY todo
    for todo in data:
        assert CANARY not in todo['content'], f\"Attacker saw victim's private todo: {todo}\"