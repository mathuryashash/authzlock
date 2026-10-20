import asyncio
from typing import Dict, Any

from app.core.config import get_config
from app.core.db import engine
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.tables import User, Priority, Category, Todo, TodoCategory
from app.users.manager import UserManager
from sqlalchemy import select


async def _seed_inner(roles: Dict[str, Any]) -> Dict[str, Any]:
    config = get_config()
    # Ensure tables exist (they should, as DB is already migrated)
    async with engine.begin() as conn:
        pass  # just to ensure connection

    # We'll use a session for the whole operation
    async with AsyncSession(engine) as session:
        # Begin transaction
        async with session.begin():
            # Load reference data: priorities and categories
            # Priorities
            result = await session.execute(select(Priority))
            priorities = result.scalars().all()
            if not priorities:
                # Insert from initial data
                priority_names = ["Low", "Medium", "High"]
                for name in priority_names:
                    session.add(Priority(name=name))
                await session.flush()
                result = await session.execute(select(Priority))
                priorities = result.scalars().all()

            # Categories: we need system categories (created_by_id is NULL) and optionally user-owned
            # First, ensure system categories exist
            result = await session.execute(select(Category).where(Category.created_by_id == None))
            system_categories = result.scalars().all()
            if not system_categories:
                category_names = ["Personal", "Work", "Home", "Health", "Social", "Entertainment"]
                for name in category_names:
                    session.add(Category(name=name))  # created_by_id remains NULL
                await session.flush()
                result = await session.execute(select(Category).where(Category.created_by_id == None))
                system_categories = result.scalars().all()

            # Prepare maps for easy access
            priority_cycle = [p.id for p in priorities]
            system_category_cycle = [c.id for c in system_categories]

            # Helper to create user via manager for password hashing
            manager = UserManager(None)  # we don't need session for hashing

            # Result dict
            result_dict = {}

            # We'll also keep track of user-owned categories for each identity
            user_owned_categories = {}  # identity_name -> category_id (int)

            for identity_name, data in roles.items():
                spec = data["spec"]
                token = data["token"]
                password = data["password"]

                # Determine user attributes
                is_superuser = spec.get("superuser", False)
                is_active = spec.get("is_active", True)  # default True unless specified
                owns_items = spec.get("owns_items", 0)

                # Build email and username with canary token in local part
                local_part = f"{token}_{identity_name}"
                email = f"{local_part}@example.com"

                # Hash password using manager's password helper
                hashed_password = manager.password_helper.hash(password)

                # Create user instance
                user = User(
                    email=email,
                    hashed_password=hashed_password,
                    is_superuser=is_superuser,
                    is_active=is_active,
                )
                session.add(user)
                await session.flush()  # to get user.id

                user_id = user.id  # keep as UUID, but we'll convert to string later for output

                # Create a category owned by this user (if not system)
                owned_category = Category(name=f"{token}_category", created_by_id=user.id)
                session.add(owned_category)
                await session.flush()
                user_owned_categories[identity_name] = owned_category.id  # integer

                # Create owned items (todos)
                owned_ids = []
                for i in range(owns_items):
                    todo_content = f"{token} todo {i}"
                    # Assign priority cycling
                    priority_id = priority_cycle[i % len(priority_cycle)]
                    # Assign a category: we'll use the user-owned category for this user
                    category_id = int(user_owned_categories[identity_name])  # ensure int

                    todo = Todo(
                        content=todo_content,
                        is_completed=False,
                        priority_id=priority_id,
                        created_by_id=user.id,
                    )
                    session.add(todo)
                    await session.flush()  # to get todo.id

                    # Link to category via todo_category
                    todo_category = TodoCategory(todo_id=todo.id, category_id=category_id)
                    session.add(todo_category)

                    owned_ids.append(str(todo.id))  # IDs as strings for output

                result_dict[identity_name] = {
                    "user_id": str(user_id),
                    "email": email,
                    "items": owned_ids,
                }

            # Commit is handled by the outer async with session.begin()
            return result_dict


def seed(roles: dict) -> dict:
    # Run the async seeding function
    return asyncio.run(_seed_inner(roles))