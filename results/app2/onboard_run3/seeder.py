import os
# Disable email sending to avoid SMTP errors
os.environ['SMTP_HOST'] = ''
os.environ['SMTP_PORT'] = ''
os.environ['EMAILS_FROM_EMAIL'] = ''

import asyncio
import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_config
from app.models.tables import User, Priority, Category, Todo
from app.core.db import Session  # async sessionmaker
from fastapi_users.password import PasswordHelper

config = get_config()
# Ensure emails are disabled by setting the attribute (though validator may not re-run)
config.EMAILS_ENABLED = False


def seed(roles):
    """Synchronous entry point for authz.lock."""
    try:
        return asyncio.run(_seed_async(roles))
    except RuntimeError as e:
        if "Event loop is closed" in str(e):
            # If there is an existing loop, we can use it
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(_seed_async(roles))
        else:
            raise


async def _seed_async(roles):
    async with Session() as session:
        # Load initial data for priorities and categories
        with open('todos/scripts/initial_data.json', 'r') as f:
            initial_data = json.load(f)

        # Ensure priorities exist
        for name in initial_data.get('priorities_names', []):
            result = await session.execute(select(Priority).where(Priority.name == name))
            if not result.scalar_one_or_none():
                session.add(Priority(name=name))
        # Ensure system categories (created_by_id is NULL) exist
        for name in initial_data.get('categories_names', []):
            result = await session.execute(
                select(Category).where(Category.name == name, Category.created_by_id == None)
            )
            if not result.scalar_one_or_none():
                session.add(Category(name=name, created_by_id=None))
        await session.commit()

        # Fetch priorities and system categories for later use
        prio_result = await session.execute(select(Priority))
        priorities = prio_result.scalars().all()
        default_priority = priorities[0] if priorities else None

        cat_result = await session.execute(select(Category).where(Category.created_by_id == None))
        system_categories = cat_result.scalars().all()

        # Password helper
        helper = PasswordHelper()

        returns = {}
        for ident, data in roles.items():
            spec = data["spec"]
            token = data["token"]
            password = data["password"]

            # Determine email: embed token in local part
            email = f"{token}@example.com"

            # Check if user already exists (should not in fresh DB)
            result = await session.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
            if user is None:
                user = User(
                    email=email,
                    hashed_password=helper.hash(password),
                    is_active=spec.get("is_active", True),
                    is_superuser=spec.get("superuser", False),
                    is_verified=True,  # required for login
                )
                session.add(user)
                await session.flush()  # to get id

                # Debug: write to a file
                with open('debug_seeder.txt', 'a') as f:
                    f.write(f"{ident}: spec={spec}, is_active={spec.get('is_active', True)}, is_superuser={spec.get('superuser', False)}, user.is_active={user.is_active}, user.is_superuser={user.is_superuser}\\n")

            # Create owned todos
            owned_ids = []
            for i in range(spec.get("owns_items", 0)):
                todo = Todo(
                    content=f"todo-{token}-{i}",
                    is_completed=False,
                    created_by_id=user.id,
                    priority_id=default_priority.id if default_priority else None,
                )
                session.add(todo)
                await session.flush()
                owned_ids.append(str(todo.id))

            returns[ident] = {
                "user_id": str(user.id),
                "email": user.email,
                "items": owned_ids
            }

        await session.commit()
        return returns