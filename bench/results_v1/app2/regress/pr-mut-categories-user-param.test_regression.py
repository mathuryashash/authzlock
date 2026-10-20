import pytest
from httpx import AsyncClient
from tests.conftest_utils import get_tests_data
from app.core.config import get_config

config = get_config()
CANARY = "cnry-pr-mut-categories-user-param"

@pytest.mark.asyncio
async def test_categories_read_isolation_regression(client: AsyncClient):
    # Obtain tokens for two users
    tests_data = get_tests_data()
    # User A (first user)
    login_a = {
        'username': tests_data['users'][0]['email'],
        'password': tests_data['users'][0]['password'],
    }
    resp_a = await client.post(f'{config.API_V1_STR}/auth/login', data=login_a)
    assert resp_a.status_code == 200
    token_a = resp_a.json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    # User B (second user)
    login_b = {
        'username': tests_data['users'][1]['email'],
        'password': tests_data['users'][1]['password'],
    }
    resp_b = await client.post(f'{config.API_V1_STR}/auth/login', data=login_b)
    assert resp_b.status_code == 200
    token_b = resp_b.json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}

    # User B creates a private category with the CANARY in its name
    category_name = f"{CANARY}_secret"
    create_resp = await client.post(
        f'{config.API_V1_STR}/categories',
        headers=headers_b,
        json={'name': category_name}
    )
    # Expect 201 created (or 409 if duplicate; but we assume clean)
    assert create_resp.status_code == 201, f"Failed to create category: {create_resp.text}"
    created_category = create_resp.json()
    category_id = created_category['id']

    # Now User A tries to list categories, specifying User B's ID via query param
    # (this is the vector introduced in the PR)
    list_resp = await client.get(
        f'{config.API_V1_STR}/categories?user_id={category_id}',
        headers=headers_a
    )
    assert list_resp.status_code == 200
    categories = list_resp.json()

    # Verify that the CANARY-labeled category is NOT present in the list.
    # On the base branch (without the vulnerable user_id param) this should hold.
    # On the PR branch the endpoint incorrectly respects the user_id param and
    # returns User B's private category, causing the assertion to fail.
    assert not any(c['name'] == category_name for c in categories), (
        f"User A was able to see User B's private category '{category_name}' "
        f"via the ?user_id= parameter, indicating an authorization bypass."
    )