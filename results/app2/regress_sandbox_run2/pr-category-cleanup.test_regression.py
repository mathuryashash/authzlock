import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.tables import Category

CANARY = "cnry-pr-category-cleanup"


@pytest.mark.asyncio
async def test_user_cannot_delete_default_category_without_ownership(
    client: AsyncClient,
    user_token_headers: dict[str, str],
    async_session: AsyncSession,
):
    # Create a default category (created_by_id=None) containing the canary
    default_cat = Category(name=f"{CANARY}-default", created_by_id=None)
    async_session.add(default_cat)
    await async_session.commit()
    await async_session.refresh(default_cat)
    cat_id = default_cat.id

    # Attempt to delete it as a regular user
    resp = await client.delete(
        f"/api/v1/categories/{cat_id}", headers=user_token_headers
    )
    # On base branch this should be forbidden (403)
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"
    # Ensure the category still exists (optional)
    result = await async_session.get(Category, cat_id)
    assert result is not None, "Category should not have been deleted"