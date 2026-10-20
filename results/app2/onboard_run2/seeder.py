import asyncio
import json
from sqlalchemy import select
from app.core.db import Session
from app.models.tables import User, Priority, Category, Todo, TodoCategory
from app.users.manager import UserManager
from app.core.config import get_config
from fastapi_users.password import PasswordHelper
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from app.schemas.user import UserCreate


async def _seed_async(roles: dict) -> dict:
    async with Session() as session:
        # Ensure system data exists
        await _ensure_system_data(session)

        # Prepare results
        results = {}

        # Password helper for hashing
        pwd_helper = PasswordHelper()

        for ident, val in roles.items():
            spec = val["spec"]
            token = val["token"]
            password = val["password"]

            kind = spec["kind"]
            if kind not in ("login", "minted"):
                continue  # skip non-login identities for seeding

            # Determine user attributes
            is_superuser = spec.get("superuser", False)
            is_active = spec.get("is_active", True)  # default active unless specified

            # Create email containing token
            email = f"{token}_{ident}@example.com"

            # Check if user already exists
            result = await session.execute(select(User).where(User.email == email))
            existing = result.scalar_one_or_none()
            if existing:
                user = existing
                # Update password if needed? We'll keep existing.
                # But we need to ensure password matches? We'll just keep.
                # For simplicity, we'll skip creation.
            else:
                # Hash password
                hashed_password = pwd_helper.hash(password)
                user = User(
                    email=email,
                    hashed_password=hashed_password,
                    is_superuser=is_superuser,
                    is_active=is_active,
                    # email_verified? Not required for login? Might need to be True.
                    # We'll set to True to avoid verification issues.
                    is_verified=True,
                )
                session.add(user)
                await session.flush()
                await session.refresh(user)

            # Create owned items (todos)
            owned_count = spec.get("owns_items", 0)
            owned_todo_ids = []

            # We'll need a priority and a category for each todo.
            # Fetch a system priority (first one) and a system category (first one) to use.
            # Alternatively, create a personal category for the user.
            # Let's create a personal category for the user to ensure ownership.
            personal_category = Category(name=f"{token}_{ident}_category", created_by_id=user.id)
            session.add(personal_category)
            await session.flush()  # to get ID

            # Get a system priority (we can use the first priority)
            result = await session.execute(select(Priority).limit(1))
            priority = result.scalar_one()
            if priority is None:
                # fallback: create a default priority
                priority = Priority(name="Medium")
                session.add(priority)
                await session.flush()

            for i in range(owned_count):
                todo_content = f"{token}_{ident}_todo_{i}"
                todo = Todo(
                    content=todo_content,
                    is_completed=False,
                    created_by_id=user.id,
                    priority_id=priority.id,
                )
                session.add(todo)
                await session.flush()
                # Link todo to personal category
                todo_category = TodoCategory(todo_id=todo.id, category_id=personal_category.id)
                session.add(todo_category)
                await session.flush()
                owned_todo_ids.append(str(todo.id))

            # Commit after each user? We'll commit at the end.
            results[ident] = {
                "user_id": str(user.id),
                "email": user.email,
                "items": owned_todo_ids,
            }

        await session.commit()
        return results


async def _ensure_system_data(session: Session) -> None:
    # Load initial data
    with open('todos/scripts/initial_data.json') as f:
        initial_data = json.load(f)

    # Priorities
    for name in initial_data.get("priorities_names", []):
        result = await session.execute(select(Priority).where(Priority.name == name))
        if not result.scalar_one_or_none():
            session.add(Priority(name=name))

    # System categories (created_by_id NULL)
    for name in initial_data.get("categories_names", []):
        result = await session.execute(
            select(Category).where(Category.name == name, Category.created_by_id == None)
        )
        if not result.scalar_one_or_none():
            session.add(Category(name=name, created_by_id=None))

    await session.commit()


def seed(roles: dict) -> dict:
    return asyncio.run(_seed_async(roles))