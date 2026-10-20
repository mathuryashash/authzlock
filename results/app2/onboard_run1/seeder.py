import asyncio
from typing import Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

# Import app modules
from app.core.config import get_config
from app.models.tables import User, Priority, Category, Todo, TodoCategory
from app.users.manager import UserManager
from fastapi_users.db import SQLAlchemyUserDatabase

config = get_config()

# Engine for seeding (use async engine from config)
engine = create_async_engine(config.POSTGRES_URI)
async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def _seed(roles: Dict[str, Any]) -> Dict[str, Any]:
    async with async_session_maker() as session:
        # Load initial data (priorities, categories) if needed
        from todos.scripts.initial_data import initiate_data
        await initiate_data(session)
        await session.commit()

        # Prepare results
        result: Dict[str, Any] = {}

        # Helper to create user with canary
        for ident, spec in roles.items():
            kind = spec["spec"]["kind"]
            if kind not in ("login", "minted"):
                continue
            token = spec["token"]
            password = spec["password"]
            # Determine email and username containing token
            email_local = f"{ident}_{token}"
            email = f"{email_local}@example.com"
            is_superuser = spec["spec"].get("superuser", False)
            is_active = spec["spec"].get("is_active", True)

            # Check if user already exists (by email)
            stmt = select(User).where(User.email == email)
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()
            if existing:
                user = existing
                # Update password to ensure can log in
                user_db = SQLAlchemyUserDatabase(session, User)
                user_manager = UserManager(user_db)
                await user_manager.update_password(password, user)
                # Update is_active and is_superuser if needed
                changed = False
                if user.is_active != is_active:
                    user.is_active = is_active
                    changed = True
                if user.is_superuser != is_superuser:
                    user.is_superuser = is_superuser
                    changed = True
                if changed:
                    session.add(user)
                await session.refresh(user)
            else:
                # Create user via manager
                user_db = SQLAlchemyUserDatabase(session, User)
                user_manager = UserManager(user_db)
                # Create dict with email and password
                user_dict = {
                    "email": email,
                    "password": password,
                }
                user = await user_manager.create(user_dict, safe=False)
                # Set is_active and is_superuser
                user.is_active = is_active
                user.is_superuser = is_superuser
                session.add(user)
                await session.refresh(user)

            # Store user info
            result[ident] = {
                "user_id": str(user.id),
                "email": user.email,
                "items": []
            }

            # Create owned items (todos) for this user
            owned_count = spec["spec"].get("owns_items", 0)
            for i in range(owned_count):
                # Create a todo with content containing token and index
                todo_content = f"{token}_todo_{i}"
                # Get a default priority (first one)
                stmt_pri = select(Priority).limit(1)
                pri_res = await session.execute(stmt_pri)
                priority = pri_res.scalar_one()
                # Create todo
                todo = Todo(
                    content=todo_content,
                    is_completed=False,
                    created_by_id=user.id,
                    priority_id=priority.id
                )
                session.add(todo)
                await session.flush()  # get todo.id
                # Assign a shared category (created_by_id NULL) if exists
                stmt_cat = select(Category).where(Category.created_by_id == None).limit(1)
                cat_res = await session.execute(stmt_cat)
                category = cat_res.scalar_one_or_none()
                if category:
                    tc = TodoCategory(todo_id=todo.id, category_id=category.id)
                    session.add(tc)
                # Record id
                result[ident]["items"].append(str(todo.id))

        await session.commit()
        return result

def seed(roles: Dict[str, Any]) -> Dict[str, Any]:
    return asyncio.run(_seed(roles))