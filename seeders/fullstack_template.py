"""Hand-written reference seeder for fastapi/full-stack-fastapi-template (the pre-hackathon prototype's).
The agent writes its own version of this file into .authzlock/artifacts/seeder.py; the D2 acceptance
check compares the verdicts the two produce.

Contract (probe_worker.py --seeder): seed(roles) -> {role: {"user_id", "email", "items"}}
  roles = {role: {"spec": manifest identity spec, "token": canary, "password": pw}}
Every seeded row must carry the role's canary token. Runs with cwd=<checkout>/backend, DB already migrated.
"""
from sqlmodel import Session

from app import crud
from app.core.config import settings
from app.core.db import engine, init_db
from app.core.security import get_password_hash
from app.models import Item, UserCreate

NAMES = {"user_a": "Asha Rao", "user_b": "Bilal Khan", "superuser": "Sofia Admin", "inactive": "Ivan Idle"}
WORDS = ["vendor notes", "salary sheet", "trip plan", "draft contract", "invoice", "roadmap", "medical form"]


def seed(roles: dict) -> dict:
    out = {}
    with Session(engine) as s:
        init_db(s)
        for role, r in roles.items():
            spec, tok, pw = r["spec"], r["token"], r["password"]
            if spec.get("superuser"):
                user = crud.get_user_by_email(session=s, email=settings.FIRST_SUPERUSER)
                user.full_name = f"{NAMES.get(role, role)} {tok}"
                user.hashed_password = get_password_hash(pw)
                s.add(user)
                s.commit()
                s.refresh(user)
            else:
                user = crud.create_user(session=s, user_create=UserCreate(
                    email=f"{role.replace('_', '.')}.{tok}@example.com", password=pw,
                    full_name=f"{NAMES.get(role, role)} {tok}", is_active=spec.get("is_active", True)))
            items = []
            for i in range(spec.get("owns_items", 0)):
                it = Item(title=f"{WORDS[i % len(WORDS)]} {tok}{i}", description=f"private to {role} {tok}",
                          owner_id=user.id)
                s.add(it)
                s.commit()
                s.refresh(it)
                items.append(str(it.id))
            out[role] = {"user_id": str(user.id), "email": user.email, "items": items}
    engine.dispose()
    return out
