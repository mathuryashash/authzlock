import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.core.config import get_config
from tests.conftest_utils import get_tests_data
from app.models.tables import User, Category

config = get_config()
API_TODOS_PREFIX = f'{config.API_V1_STR}/todos'
CANARY = "cnry-pr-mut-foreign-category-link"


@pytest.mark.asyncio
async def test_foreign_category_link_isolation(client: AsyncClient, async_session):
    tests_data = get_tests_data()

    # retrieve user0 and user1 from DB
    res = await async_session.execute(select(User).where(User.email == tests_data['users'][0]['email']))
    user0 = res.scalar_one()
    res = await async_session.execute(select(User).where(User.email == tests_data['users'][1]['email']))
    user1 = res.scalar_one()

    # get a private category belonging to each user
    res = await async_session.execute(select(Category).where(Category.created_by_id == user0.id).limit(1))
    cat0 = res.scalar_one()
    res = await async_session.execute(select(Category).where(Category.created_by_id == user1.id).limit(1))
    cat1 = res.scalar_one()

    # obtain auth header for user0
    login_resp = await client.post(
        f'{config.API_V1_STR}/auth/login',
        data={'username': user0.email, 'password': tests_data['users'][0]['password']},
    )
    assert login_resp.status_code == 200
    token0 = login_resp.json()['access_token']
    headers0 = {'Authorization': f'Bearer {token0}'}

    # attempt to create a todo for user0 using user1's private category (should be forbidden)
    todo_payload = {
        'content': f'Test {CANARY}',
        'priority_id': 1,  # assuming priority 1 exists in seed data
        'categories_ids': [cat1.id],
    }
    resp = await client.post(API_TODOS_PREFIX, headers=headers0, json=todo_payload)

    # the request must be rejected with a validation error
    assert resp.status_code == 400
    # ensure the todo was not created (the CANARY must not appear in user0's todo list)
    list_resp = await client.get(API_TODOS_PREFIX, headers=headers0)
    assert list_resp.status_code == 200
    todos = list_resp.json()
    assert all(CANARY not in t['content'] for t in todos)