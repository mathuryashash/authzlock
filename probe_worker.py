"""
authz.lock probe worker.

Runs INSIDE one checkout of the target app (cwd = <checkout>/backend) with the app's own
virtualenv. It:
  1. builds a fresh seed database (alembic migrations of THIS checkout),
  2. seeds identities + owned objects, every value carrying a random per-run canary token,
  3. logs the normal identities in through the real login endpoint, mints the invalid ones,
  4. discovers every operation from the app's own OpenAPI schema,
  5. probes operation x identity x target x variant, each probe on a fresh
     `CREATE DATABASE ... TEMPLATE seed` clone, recording status, which owners' canaries
     leaked (response + outgoing email), and a row-level DB diff with owner attribution.

Output: raw JSON observations. Verdicts are computed by authzlock.py, never here.
In the full product the seeder and request synthesis below are written/repaired by a
Nemotron agent inside Token Factory Sandboxes; in this prototype they are rule-based.
"""
import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import logging

import psycopg

logging.getLogger("httpx").setLevel(logging.WARNING)

ap = argparse.ArgumentParser()
ap.add_argument("--manifest", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--tag", required=True)
ap.add_argument("--pg", default="postgresql://postgres@localhost:5432/postgres")
ap.add_argument("--smtp-port", type=int, default=1025)
args = ap.parse_args()

MAN = json.load(open(args.manifest))
PREFIX = MAN["api_prefix"]
TAG = re.sub(r"[^a-z0-9_]", "_", args.tag.lower())
SEED_DB = f"authz_seed_{TAG}"
PG_BASE = args.pg.rsplit("/", 1)[0]


def db_url(name: str, driver: str = "postgresql+psycopg") -> str:
    return PG_BASE.replace("postgresql", driver, 1) + "/" + name


admin = psycopg.connect(args.pg, autocommit=True)


def drop_db(name: str) -> None:
    admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


# ---------------------------------------------------------------- 1. seed database
drop_db(SEED_DB)
admin.execute(f'CREATE DATABASE "{SEED_DB}"')
env = dict(os.environ, DATABASE_URL=db_url(SEED_DB, "postgresql"), SMTP_PORT=str(args.smtp_port))
os.environ.update(env)
mig = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], env=env,
                     capture_output=True, text=True)
if mig.returncode != 0:
    print(mig.stderr[-2000:], file=sys.stderr)
    sys.exit("migration failed")

sys.path.insert(0, os.getcwd())
import jwt  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlmodel import Session  # noqa: E402

from app import crud  # noqa: E402
from app.api import deps  # noqa: E402
from app.core import security  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.db import engine as module_engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Item, User, UserCreate  # noqa: E402

FIRST_NAMES = {"user_a": "Asha Rao", "user_b": "Bilal Khan", "superuser": "Sofia Admin",
               "inactive": "Ivan Idle"}
ITEM_WORDS = ["vendor notes", "salary sheet", "trip plan", "draft contract", "invoice",
              "roadmap", "medical form"]

roles: dict[str, dict] = {}
with Session(module_engine) as s:
    init_db(s)
    su = crud.get_user_by_email(session=s, email=settings.FIRST_SUPERUSER)
    for role, spec in MAN["identities"].items():
        if spec["kind"] not in ("login", "minted"):
            continue
        tok = secrets.token_hex(5)  # per-run random canary token
        pw = "Pw-" + secrets.token_hex(8)
        if spec.get("superuser"):
            user = su
            user.full_name = f"{FIRST_NAMES[role]} {tok}"
            user.hashed_password = security.get_password_hash(pw)
            s.add(user)
            s.commit()
            s.refresh(user)
        else:
            user = crud.create_user(session=s, user_create=UserCreate(
                email=f"{role.replace('_', '.')}.{tok}@example.com", password=pw,
                full_name=f"{FIRST_NAMES[role]} {tok}",
                is_active=spec.get("is_active", True)))
        items = []
        for i in range(spec.get("owns_items", 0)):
            it = Item(title=f"{ITEM_WORDS[i % len(ITEM_WORDS)]} {tok}{i}",
                      description=f"private to {role} {tok}", owner_id=user.id)
            s.add(it)
            s.commit()
            s.refresh(it)
            items.append(str(it.id))
        roles[role] = {"user_id": str(user.id), "email": user.email, "password": pw,
                       "token": tok, "items": items}
module_engine.dispose()
admin.execute(f'ALTER DATABASE "{SEED_DB}" ALLOW_CONNECTIONS false')
role_by_user_id = {v["user_id"]: k for k, v in roles.items()}

# canary strings per role (exact, case-sensitive)
canaries = {r: [v["token"], v["email"], v["user_id"], *v["items"]] for r, v in roles.items()}

# ---------------------------------------------------------------- per-probe DB clones
_clone_n = 0


class Holder:
    engine = None


H = Holder()


def get_db_override():
    with Session(H.engine) as session:
        yield session


app.dependency_overrides[deps.get_db] = get_db_override


def new_clone():
    global _clone_n
    _clone_n += 1
    name = f"authz_c_{TAG}_{_clone_n}"
    admin.execute(f'CREATE DATABASE "{name}" TEMPLATE "{SEED_DB}"')
    H.engine = create_engine(db_url(name), poolclass=None)
    return name


def end_clone(name):
    H.engine.dispose()
    H.engine = None
    drop_db(name)


def snapshot(engine) -> dict:
    snap = {}
    with engine.connect() as c:
        tables = [r[0] for r in c.execute(text(
            "select table_name from information_schema.tables where table_schema='public' "
            "and table_type='BASE TABLE' and table_name <> 'alembic_version'"))]
        for t in tables:
            rows = c.execute(text(f'select * from "{t}"')).mappings().all()
            snap[t] = {str(r.get("id", i)): {k: (None if v is None else str(v)) for k, v in r.items()}
                       for i, r in enumerate(rows)}
    return snap


def row_owner(table: str, row: dict) -> str:
    own = MAN["ownership"].get(table, {})
    if own.get("owner") == "self":
        return role_by_user_id.get(row.get("id"), "new")
    col = own.get("owner_column")
    if col:
        return role_by_user_id.get(row.get(col), "unknown")
    return "unowned"


def db_diff(before: dict, after: dict) -> list[dict]:
    effects = []
    ignored = set(MAN["ignored_columns"])
    for t in set(before) | set(after):
        b, a = before.get(t, {}), after.get(t, {})
        priv = set(MAN["privilege_columns"].get(t, []))
        for pk in set(b) | set(a):
            if pk not in a:
                effects.append({"table": t, "op": "delete", "owner": row_owner(t, b[pk])})
            elif pk not in b:
                e = {"table": t, "op": "insert", "owner": row_owner(t, a[pk])}
                if any(a[pk].get(c) == "True" for c in priv if c != "is_active"):
                    e["privileged_insert"] = True
                effects.append(e)
            else:
                changed = sorted(c for c in a[pk] if c not in ignored and a[pk][c] != b[pk].get(c))
                if changed:
                    e = {"table": t, "op": "update", "owner": row_owner(t, b[pk]),
                         "columns": changed}
                    if priv & set(changed):
                        e["privilege_change"] = sorted(priv & set(changed))
                    if row_owner(t, a[pk]) != row_owner(t, b[pk]):
                        e["new_owner"] = row_owner(t, a[pk])
                    effects.append(e)
    return sorted(effects, key=lambda e: json.dumps(e, sort_keys=True))


# ---------------------------------------------------------------- SMTP sink (out-of-band leaks)
mailbox: list[tuple[list[str], str]] = []
try:
    from aiosmtpd.controller import Controller

    class Sink:
        async def handle_DATA(self, server, session, envelope):
            mailbox.append((list(envelope.rcpt_tos), envelope.content.decode("utf8", "replace")))
            return "250 OK"

    smtp = Controller(Sink(), hostname="127.0.0.1", port=args.smtp_port)
    smtp.start()
except Exception as ex:  # pragma: no cover
    print("SMTP sink unavailable:", ex, file=sys.stderr)

# ---------------------------------------------------------------- identities
client = TestClient(app, raise_server_exceptions=False)
seed_snapshot = None
tokens: dict[str, str | None] = {}
name = new_clone()
seed_snapshot = snapshot(H.engine)
for role, spec in MAN["identities"].items():
    k = spec["kind"]
    if k == "anonymous":
        tokens[role] = None
    elif k == "login":  # real login path, every run
        r = client.post(f"{PREFIX}/login/access-token",
                        data={"username": roles[role]["email"], "password": roles[role]["password"]})
        if r.status_code != 200:
            sys.exit(f"login failed for {role}: {r.status_code} {r.text}")
        tokens[role] = r.json()["access_token"]
    elif k == "minted":
        tokens[role] = security.create_access_token(roles[role]["user_id"], timedelta(minutes=30))
    elif k == "forged":
        tokens[role] = jwt.encode({"sub": roles[spec["as"]]["user_id"],
                                   "exp": datetime.now(UTC) + timedelta(minutes=30)},
                                  "not-the-real-key-" + secrets.token_hex(8), algorithm="HS256")
    elif k == "expired":
        tokens[role] = jwt.encode({"sub": roles[spec["as"]]["user_id"],
                                   "exp": datetime.now(UTC) - timedelta(minutes=5)},
                                  settings.SECRET_KEY, algorithm=security.ALGORITHM)
    elif k == "alg_none":
        tokens[role] = jwt.encode({"sub": roles[spec["as"]]["user_id"],
                                   "exp": datetime.now(UTC) + timedelta(minutes=30)},
                                  None, algorithm="none")
    elif k == "deleted":
        tokens[role] = security.create_access_token(str(uuid.uuid4()), timedelta(minutes=30))
end_clone(name)

# ---------------------------------------------------------------- operation discovery
schema = app.openapi()
components = schema.get("components", {}).get("schemas", {})


def resolve(s: dict) -> dict:
    while "$ref" in s:
        s = components[s["$ref"].split("/")[-1]]
    if "anyOf" in s:
        non_null = [x for x in s["anyOf"] if x.get("type") != "null"]
        if non_null:
            return resolve(non_null[0])
    return s


counter = [0]


def gen_value(name: str, s: dict, caller: str | None):
    s = resolve(s)
    counter[0] += 1
    n = counter[0]
    t, fmt = s.get("type"), s.get("format")
    if "password" in name:
        if name == "current_password":
            return roles.get(caller, {}).get("password", "Wrong-pw-123456")
        return "N3w-" + secrets.token_hex(8)
    if name == "token":
        return "not-a-valid-reset-token"
    if fmt == "email" or name in ("email", "email_to", "username"):
        return f"probe{n}.{secrets.token_hex(3)}@example.com"
    if fmt == "uuid":
        return str(uuid.uuid4())
    if t == "boolean":
        return False
    if t == "integer":
        return 1
    if t == "number":
        return 1.0
    if t == "array":
        return []
    return f"probe-{n}"


def gen_body(s: dict, caller: str | None) -> dict:
    s = resolve(s)
    props = s.get("properties", {})
    req = s.get("required", [])
    chosen = req or [p for p in props if resolve(props[p]).get("type") == "string"
                     and "password" not in p and "email" not in p][:1]
    return {p: gen_value(p, props[p], caller) for p in chosen}


def target_value(hint: str, target: str):
    if target == "nonexistent":
        return f"ghost.{secrets.token_hex(3)}@example.com" if hint == "user_email" else str(uuid.uuid4())
    r = roles[target]
    return {"item_id": (r["items"] or [str(uuid.uuid4())])[0], "user_id": r["user_id"],
            "user_email": r["email"]}[hint]


ops = []
for path, methods in schema["paths"].items():
    if not path.startswith(PREFIX):
        continue
    for method, op in methods.items():
        if method not in ("get", "post", "put", "patch", "delete"):
            continue
        params = op.get("parameters", [])
        path_params = [p["name"] for p in params if p["in"] == "path"]
        unsupported = [p for p in path_params if p not in MAN["param_hints"]]
        body_kind, body_schema = None, None
        content = op.get("requestBody", {}).get("content", {})
        if "application/json" in content:
            body_kind, body_schema = "json", content["application/json"]["schema"]
        elif "application/x-www-form-urlencoded" in content:
            body_kind, body_schema = "form", content["application/x-www-form-urlencoded"]["schema"]
        ops.append({"key": f"{method.upper()} {path[len(PREFIX):]}", "method": method.upper(),
                    "path": path, "params": params, "path_params": path_params,
                    "unsupported": unsupported, "body_kind": body_kind, "body_schema": body_schema})

# ---------------------------------------------------------------- probing
def caller_role(identity: str) -> str | None:
    return identity if identity in roles and identity not in MAN["invalid_identities"] else (
        "inactive" if identity == "inactive" else None)


results = []
t0 = time.time()
for op in ops:
    creds_op = op["body_kind"] == "form" and "password" in resolve(op["body_schema"]).get("properties", {})
    if op["unsupported"]:
        results.append({"op": op["key"], "unsupported": op["unsupported"]})
        continue
    targets = MAN["targets"] if (op["path_params"] or creds_op) else ["-"]
    variants = ["base"]
    if op["body_kind"] == "json" and op["method"] in ("POST", "PUT", "PATCH"):
        variants.append("hostile")
    if creds_op:
        variants = ["valid_creds", "wrong_password"]
    for identity in MAN["identities"]:
        for target in targets:
            for variant in variants:
                caller = caller_role(identity)
                url = op["path"]
                for p in op["path_params"]:
                    url = url.replace("{" + p + "}", str(target_value(MAN["param_hints"][p], target)))
                query = {p["name"]: gen_value(p["name"], p.get("schema", {}), caller)
                         for p in op["params"] if p["in"] == "query" and p.get("required")}
                kw = {"params": query}
                if op["body_kind"] == "json":
                    body = gen_body(op["body_schema"], caller)
                    if variant == "hostile":
                        victim = "user_b" if identity != "user_b" else "user_a"
                        body.update({"is_superuser": True, "is_active": True,
                                     "owner_id": roles[victim]["user_id"]})
                    kw["json"] = body
                elif op["body_kind"] == "form":
                    if creds_op and target != "nonexistent":
                        kw["data"] = {"username": roles[target]["email"],
                                      "password": roles[target]["password"] if variant == "valid_creds"
                                      else "Wrong-pw-" + secrets.token_hex(4)}
                    else:
                        kw["data"] = {"username": f"ghost.{secrets.token_hex(3)}@example.com",
                                      "password": "Wrong-pw-123456"}
                headers = {"Authorization": f"Bearer {tokens[identity]}"} if tokens[identity] else {}
                request_text = url + json.dumps(kw, default=str)
                cname = new_clone()
                mailbox.clear()
                try:
                    r = client.request(op["method"], url, headers=headers, **kw)
                    status, body_text = r.status_code, r.text
                except Exception as ex:  # app crashed outside the ASGI error handler
                    status, body_text, err = 599, "", f"{type(ex).__name__}: {ex}"[:200]
                else:
                    err = None
                time.sleep(0.02) if mailbox else None
                after = snapshot(H.engine)
                end_clone(cname)
                # leaks: canaries of any role in the response, excluding strings we sent ourselves
                leaks = sorted(role for role, cs in canaries.items()
                               if any(c in body_text and c not in request_text for c in cs))
                smtp_leaks = sorted({role for rcpts, msg in mailbox for role, cs in canaries.items()
                                     if any(c in msg for c in cs)
                                     and not any(roles[role]["email"] in rc for rc in rcpts)})
                count = None
                try:
                    j = r.json()
                    if isinstance(j, dict) and isinstance(j.get("count"), int):
                        count = j["count"]
                except Exception:
                    pass
                results.append({"op": op["key"], "identity": identity, "target": target,
                                "variant": variant, "status": status, "leaks": leaks,
                                "smtp_leaks": smtp_leaks, "db": db_diff(seed_snapshot, after),
                                "count": count, "error": err})

drop_db(SEED_DB)
out = {"tag": args.tag, "elapsed_s": round(time.time() - t0, 1), "probes": len(results),
       "roles": {r: {"owns_items": len(v["items"])} for r, v in roles.items()},
       "public_operations": MAN["public_operations"], "results": results}
json.dump(out, open(args.out, "w"), indent=1)
print(f"[{args.tag}] {len(results)} probes in {out['elapsed_s']}s")
os._exit(0)
