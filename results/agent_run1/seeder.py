import uuid
from typing import Any

from sqlmodel import Session, create_engine, select

import sys
sys.path.append("/app/backend")  # ensure we can import app modules

from app import crud
from app.core.config import settings
from app.core.db import engine
from app.models import User, Item, ItemCreate


def seed(roles: dict[str, dict]) -> dict[str, dict]:
    # roles: identity name -> {"spec": spec, "token": canary, "password": password}
    # We'll create engine ourselves; but note that core.db already has engine.
    # However we need a fresh session; we can use the engine from core.db.
    # Ensure we close connections after.
    from sqlmodel import Session

    # Use the existing engine from core.db (already configured with DATABASE_URL)
    # but we need to import it inside function to avoid early import issues?
    # We'll just import engine from app.core.db as above.

    created: dict[str, dict] = {}

    with Session(engine) as session:
        for name, data in roles.items():
            spec = data["spec"]
            token = data["token"]
            password = data["password"]
            kind = spec.get("kind")
            if kind in ("login", "minted"):
                # Determine email and full_name with token
                email_local = f"{token}_{name}"
                # Ensure email domain is example.com (or any)
                email = f"{email_local}@example.com"
                full_name = f"{token} {name}"
                is_active = spec.get("is_active", True)
                is_superuser = spec.get("superuser", False)
                # For superuser, we need to update the existing FIRST_SUPERUSER if exists
                if is_superuser:
                    # Find existing superuser by settings.FIRST_SUPERUSER
                    stmt = select(User).where(User.email == settings.FIRST_SUPERUSER)
                    user = session.exec(stmt).first()
                    if user:
                        # Update password and ensure is_superuser True, is_active as per spec? Usually superuser active.
                        user.hashed_password = crud.get_password_hash(password)
                        user.is_active = is_active
                        user.is_superuser = True
                        user.full_name = full_name
                        session.add(user)
                    else:
                        # Create new superuser
                        user_in = crud.UserCreate(
                            email=settings.FIRST_SUPERUSER,
                            password=password,
                            is_superuser=True,
                            is_active=is_active,
                            full_name=full_name,
                        )
                        user = crud.create_user(session=session, user_create=user_in)
                else:
                    # Regular user
                    user_in = crud.UserCreate(
                        email=email,
                        password=password,
                        is_active=is_active,
                        is_superuser=False,
                        full_name=full_name,
                    )
                    user = crud.create_user(session=session, user_create=user_in)
                # Create owned items
                owned_items = []
                for _ in range(spec.get("owns_items", 0)):
                    item_in = crud.ItemCreate(
                        title=f"{token} item",
                        description=f"{token} description",
                    )
                    item = crud.create_item(
                        session=session, item_in=item_in, owner_id=user.id
                    )
                    owned_items.append(str(item.id))
                # Refresh user to get id etc.
                session.refresh(user)
                created[name] = {
                    "user_id": str(user.id),
                    "email": user.email,
                    "items": owned_items,
                }
            elif kind == "anonymous":
                # No seeding needed
                continue
            else:
                # forged, expired, alg_none, deleted are handled by manifest; no seeding
                continue
        session.commit()
    return created