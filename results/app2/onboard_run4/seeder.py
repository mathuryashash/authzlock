import asyncio
import uuid
from typing import Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_config
from app.models.tables import User, Priority, Category, Todo, TodoCategory
from app.users.manager import UserManager
from fastapi_users.db import SQLAlchemyUserDatabase


def seed(roles: Dict[str, Any]) -> Dict[str, Any]:
    config = get_config()
    engine = create_async_engine(config.POSTGRES_URI, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _seed() -> Dict[str, Any]:
        async with async_session() as session:
            # Ensure initial data (priorities, categories) exist
            from scripts.initial_data import initiate_data
            await initiate_data(session)

            result: Dict[str, Any] = {}

            for ident, spec in roles.items():
                if spec["spec"]["kind"] not in ("login", "minted"):
                    continue
                token = spec["token"]
                password = spec["password"]
                owns = spec["spec"].get("owns_items", 0)
                is_superuser = spec["spec"].get("superuser", False)
                is_active = spec["spec"].get("is_active", True)

                # Create user email with token in local part
                email = f"{token}@{ident}.example.com"

                # Check if user already exists
                stmt = select(User).where(User.email == email)
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()
                if existing:
                    user = existing
                else:
                    user = User(
                        email=email,
                        hashed_password="",  # will be set
                        is_active=is_active,
                        is_superuser=is_superuser,
                        is_verified=False,
                    )
                    session.add(user)
                    await session.flush()  # get id

                # Set password via UserManager's password helper
                user_db = SQLAlchemyUserDatabase(session, User)
                manager = UserManager(user_db)
                hashed = manager.password_helper.hash(password)
                user.hashed_password = hashed
                session.add(user)

                # Create owned todos
                owned_ids = []
                for i in range(owns):
                    todo_content = f"{token} todo {i}"
                    # Get a priority (any)
                    prio_stmt = select(Priority).limit(1)
                    prio_res = await session.execute(prio_stmt)
                    priority = prio_res.scalar_one()
                    # Get a system category (created_by_id is NULL)
                    cat_stmt = select(Category).where(Category.created_by_id == None).limit(1)
                    cat_res = await session.execute(cat_stmt)
                    category = cat_res.scalar_one()
                    # Create todo
                    todo = Todo(
                        content=todo_content,
                        is_completed=False,
                        priority_id=priority.id,
                        created_by_id=user.id,
                    )
                    session.add(todo)
                    await session.flush()
                    # Link category
                    todo_cat = TodoCategory(todo_id=todo.id, category_id=category.id)
                    session.add(todo_cat)
                    owned_ids.append(str(todo.id))

                result[ident] = {
                    "user_id": str(user.id),
                    "email": user.email,
                    "items": owned_ids,
                }

            await session.commit()
            return result

    return asyncio.run(_seed())