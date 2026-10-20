import pytest
from httpx import AsyncClient
from tests.conftest_utils import get_tests_data
from app.core.config import get_config

config = get_config()
API_TODOS_PREFIX = f'{config.API_V1_STR}/todos'


@pytest.mark.asyncio
async def test_read_isolation_regression(client, user_token_headers):
    # user0 token from fixture
    headers_user0 = user_token_headers
    # get user1 credentials
    tests_data = get_tests_data()
    user1 = tests_data['users'][1]
    login_data = {'username': user1['email'], 'password': user1['password']}
    resp = await client.post(f'{config.API_V1_STR}/auth/login', data=login_data)
    assert resp.status_code == 200
    token_user1 = resp.json()['access_token']
    headers_user1 = {'Authorization': f'Bearer {token_user1}'}
    # create a todo for user1 with CANARY in content
    ca = 'cnry-pr-mut-swap-user-source'
    todo_data = {'content': f'Important {ca}', 'priority_id': 1, 'categories_ids': [1]}
    resp = await client.post(API_TODOS_PREFIX, headers=headers_user1, json=todo_data)
    assert resp.status_code == 201
    # As user0, try to fetch todos specifying user_id of user1 (assume id=2)
    params = {'user_id': 2}
    resp = await client.get(API_TODOS_PREFIX, headers=headers_user0, params=params)
    assert resp.status_code == 200
    todos = resp.json()
    # Ensure none of the returned todos contain the CANARY in content
    for t in todos:
        assert ca not in t['content']