import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.models.tables import Todo, User
import json

CANARY = "cnry-pr-todo-get-by-id"


@pytest.mark.asyncio
async def test_get_todo_isolation(client: AsyncClient, async_session):
    # Load test data to get credentials for two users
    with open('todos/tests/tests_data.json', 'r') as f:
        data = json.load(f)
    user_a_info = data['users'][0]  # test1@test.com
    user_b_info = data['users'][1]  # test2@test.com

    # Helper to obtain token for a given user
    async def get_token(user_info):
        login_resp = await client.post(
            '/api/v1/auth/login',
            data={'username': user_info['email'], 'password': user_info['password']},
        )
        assert login_resp.status_code == 200, login_resp.text
        token = login_resp.json()['access_token']
        return {'Authorization': f'Bearer {token}'}

    headers_a = await get_token(user_a_info)
    headers_b = await get_token(user_b_info)

    # Get user_b object from DB
    result = await async_session.execute(select(User).where(User.email == user_b_info['email']))
    user_b = result.scalar_one()
    assert user_b is not None

    # As user_b, create a todo containing the canary
    todo_b = Todo(
        content=CANARY,
        priority_id=1,  # Low priority exists
        created_by_id=user_b.id,
        todos_categories=[],  # no categories for simplicity
    )
    async_session.add(todo_b)
    await async_session.commit()
    await async_session.refresh(todo_b)
    todo_id = todo_b.id

    # Now user_a attempts to fetch user_b's todo
    resp = await client.get(
        f'/api/v1/todos/{todo_id}',
        headers=headers_a,
    )
    # Expect isolation: either not found or forbidden, and certainly no canary leaked
    assert CANARY not in resp.text, f"Canary leaked in response: {resp.text}"