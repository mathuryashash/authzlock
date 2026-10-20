import pytest
from httpx import AsyncClient
from app.models.tables import Category

CANARY = "cnry-pr-category-cleanup"

@pytest.mark.asyncio
async def test_shared_category_delete_isolation(async_session, user_token_headers, client: AsyncClient):
    # Create a shared category (created_by_id=None) with the canary in its name
    shared_cat = Category(name=f"shared-{CANARY}", created_by_id=None)
    async_session.add(shared_cat)
    await async_session.commit()
    await async_session.refresh(shared_cat)
    cat_id = shared_cat.id

    # Verify category exists before deletion attempt
    before = await async_session.get(Category, cat_id)
    assert before is not None, "Setup failed: shared category not found"

    # Attempt to delete the shared category as a regular user
    headers = user_token_headers
    response = await client.delete(f"/categories/{cat_id}", headers=headers)

    # After deletion attempt, check if category still exists
    after = await async_session.get(Category, cat_id)
    # On base branch, deletion should be blocked, so category still exists
    # On PR branch, bug allows deletion, so category will be None
    assert after is not None, f"Shared category {cat_id} was deleted (should be isolated)"