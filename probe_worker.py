"""
authz.lock probe worker.

Runs INSIDE one checkout of the target app (cwd = <checkout>/<profile cwd>) with the app's own
virtualenv. App-specific wiring comes from the app profile (--profile-json) and the manifest's "app" section,
helpers in probe_lib.py; the defaults are app #1 (full-stack-fastapi-template). It:
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
from __future__ import annotations

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
from datetime import datetime, timedelta, timezone

UTC = timezone.utc  # py3.9 targets: datetime.UTC is 3.11+

import logging

import psycopg

logging.getLogger("httpx").setLevel(logging.WARNING)

ap = argparse.ArgumentParser()
ap.add_argument("--manifest", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--tag", required=True)
ap.add_argument("--pg", default="postgresql://postgres@localhost:5432/postgres")
ap.add_argument("--smtp-port", type=int, default=1025)
ap.add_argument("--profile-json", default="{}")
ap.add_argument("--dotenv", default="")
ap.add_argument("--seeder", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeders",
                                                 "fullstack_template.py"))
args = ap.parse_args()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lib as pl  # noqa: E402

PROF = pl.load_profile(json.loads(args.profile_json))
MAN = json.load(open(args.manifest))
APP = pl.app_section(MAN)
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
_pp = os.pathsep.join(os.path.abspath(x) for x in PROF["pythonpath"])
env = dict(os.environ, **pl.db_env(PROF["db_env"], db_url(SEED_DB, "postgresql")), SMTP_PORT=str(args.smtp_port),
           **({"PYTHONPATH": _pp} if _pp else {}))
os.environ.update(env)
mig = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], env=env,
                     capture_output=True, text=True)
if mig.returncode != 0:
    print(mig.stderr[-2000:], file=sys.stderr)
    sys.exit("migration failed")

sys.path[:0] = [os.getcwd(), *(os.path.abspath(x) for x in PROF["pythonpath"])]
import importlib  # noqa: E402

import jwt  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402


def load_attr(spec: str):
    mod, attr = spec.split(":")
    return getattr(importlib.import_module(mod), attr)


app = load_attr(PROF["asgi"])
get_db = load_attr(APP["db_dependency"])
SessionCls = load_attr(APP["session_class"])
ASYNC = SessionCls.__name__.startswith("Async")

# Seeder plugin: hand-written reference or the agent's artifact. It gets only roles/canaries/passwords;
# the gates below re-check its work against the seed DB instead of trusting what it returns.
# It runs in its own process (D5): leaked engines/event loops from LLM-written async code die with it.
want = {role: {"spec": spec, "token": secrets.token_hex(5), "password": "Pw-" + secrets.token_hex(8)}
        for role, spec in MAN["identities"].items() if spec["kind"] in ("login", "minted")}
_senv = dict(os.environ, PYTHONPATH=os.pathsep.join([os.getcwd(), *(os.path.abspath(x) for x in PROF["pythonpath"]),
                                                      os.environ.get("PYTHONPATH", "")]))
try:
    got = pl.run_seeder(os.path.abspath(args.seeder), {r: dict(v) for r, v in want.items()}, env=_senv)
except RuntimeError as e:
    sys.exit(str(e))
roles: dict[str, dict] = {}
for role, w in want.items():
    g = got.get(role)
    if not g:
        sys.exit(f"harness invalid: seeder returned nothing for {role}")
    roles[role] = {"user_id": str(g["user_id"]), "email": g["email"], "password": w["password"],
                   "token": w["token"], "items": [str(i) for i in g.get("items", [])]}
admin.execute(f'ALTER DATABASE "{SEED_DB}" ALLOW_CONNECTIONS false')
admin.execute("select pg_terminate_backend(pid) from pg_stat_activity where datname = %s", (SEED_DB,))
role_by_user_id = {v["user_id"]: k for k, v in roles.items()}

# canary strings per role (exact, case-sensitive)
canaries = {r: pl.canaries(v) for r, v in roles.items()}

# ---------------------------------------------------------------- per-probe DB clones
_clone_n = 0


class Holder:
    clone = None       # current per-probe DB name (snapshots read it with plain psycopg)
    app_engine = None  # engine the app's own session dependency gets (async for async apps)


H = Holder()

if ASYNC:
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

    async def get_db_override():
        async with SessionCls(H.app_engine, expire_on_commit=False) as session:
            yield session
else:
    def get_db_override():
        with SessionCls(H.app_engine) as session:
            yield session

app.dependency_overrides[get_db] = get_db_override


def new_clone():
    global _clone_n
    _clone_n += 1
    name = f"authz_c_{TAG}_{_clone_n}"
    drop_db(name)  # leftover from a killed run
    admin.execute(f'CREATE DATABASE "{name}" TEMPLATE "{SEED_DB}"')
    H.clone = name
    if ASYNC:  # NullPool: TestClient runs each request on a fresh event loop; pooled asyncpg conns would break
        H.app_engine = create_async_engine(db_url(name, APP["db_driver"]), poolclass=NullPool)
    else:
        H.app_engine = create_engine(db_url(name, APP["db_driver"]))
    return name


def end_clone(name):
    H.app_engine.dispose() if not ASYNC else None  # async NullPool engine holds no connections
    H.app_engine = None
    drop_db(name)


def snapshot() -> dict:
    """Plain psycopg, not SQLAlchemy: works whatever SQLAlchemy/driver the target pins (SA 1.4 has no psycopg3)."""
    from psycopg.rows import dict_row
    snap = {}
    with psycopg.connect(db_url(H.clone, "postgresql"), row_factory=dict_row) as c:
        tables = [r["table_name"] for r in c.execute(
            "select table_name from information_schema.tables where table_schema='public' "
            "and table_type='BASE TABLE' and table_name <> 'alembic_version'")]
        for t in tables:
            rows = [{k: (None if v is None else str(v)) for k, v in r.items()} for r in c.execute(f'select * from "{t}"')]
            snap[t] = {pl.row_key(r, i): r for i, r in enumerate(rows)}
    return snap


def row_owner(table: str, row: dict, snap: dict | None = None) -> str:
    return pl.row_owner(table, row, MAN["ownership"], role_by_user_id, snap or {})


def db_diff(before: dict, after: dict) -> list[dict]:
    effects = []
    ignored = set(MAN["ignored_columns"])
    for t in set(before) | set(after):
        b, a = before.get(t, {}), after.get(t, {})
        priv = set(MAN["privilege_columns"].get(t, []))
        for pk in set(b) | set(a):
            if pk not in a:
                effects.append({"table": t, "op": "delete", "owner": row_owner(t, b[pk], before)})
            elif pk not in b:
                e = {"table": t, "op": "insert", "owner": row_owner(t, a[pk], after)}
                if any(a[pk].get(c) == "True" for c in priv if c != "is_active"):
                    e["privileged_insert"] = True
                effects.append(e)
            else:
                changed = sorted(c for c in a[pk] if c not in ignored and a[pk][c] != b[pk].get(c))
                if changed:
                    e = {"table": t, "op": "update", "owner": row_owner(t, b[pk], before),
                         "columns": changed}
                    if priv & set(changed):
                        e["privilege_change"] = sorted(priv & set(changed))
                    if row_owner(t, a[pk], after) != row_owner(t, b[pk], before):
                        e["new_owner"] = row_owner(t, a[pk], after)
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
client = TestClient(app, raise_server_exceptions=bool(os.environ.get("AUTHZ_DEBUG")))
seed_snapshot = None
tokens: dict[str, str | None] = {}
name = new_clone()
seed_snapshot = snapshot()
# seeder gate input (security #3): rows each role really owns in the seed DB that carry its canary
canaried_rows = {r: sum(1 for t, rows in seed_snapshot.items() if MAN["ownership"].get(t, {}).get("owner") != "self"
                        for row in rows.values() if row_owner(t, row, seed_snapshot) == r
                        and any(v and roles[r]["token"] in v for v in row.values()))
                 for r in roles}
# Login through the app's own OAuth2 password endpoint (from its OpenAPI securitySchemes).
_schemes = app.openapi().get("components", {}).get("securitySchemes", {}).values()
LOGIN = next((f["password"]["tokenUrl"] for s in _schemes for f in [s.get("flows", {})] if "password" in f),
             f"{PREFIX}/login/access-token")
LOGIN = LOGIN if LOGIN.startswith("/") else "/" + LOGIN
# seeder gate input: the identity flags as they really are in the seed DB (not as the seeder claims)
_utable = next((t for t, o in MAN["ownership"].items() if o.get("owner") == "self"), "user")
flags = {r: {c: row.get(c) for c in ("is_superuser", "is_active") if c in row}
         for r in roles for row in [seed_snapshot.get(_utable, {}).get(roles[r]["user_id"], {})]}
for role, spec in MAN["identities"].items():
    if spec["kind"] == "login":  # real login path, every run
        r = client.post(LOGIN, data={"username": roles[role]["email"], "password": roles[role]["password"]})
        if r.status_code != 200:
            sys.exit(f"login failed for {role}: {r.status_code} {r.text}")
        tokens[role] = r.json()["access_token"]
# Every other token copies a real login token's claim layout (sub vs user_id, aud, ...), with the identity swapped.
_ref = next(r for r, sp in MAN["identities"].items() if sp["kind"] == "login")
CLAIMS, ALG = pl.token_shape(tokens[_ref])
SECRET = os.environ.get(APP["jwt_secret_setting"]) or pl.read_dotenv(args.dotenv).get(APP["jwt_secret_setting"], "")


def mint(as_role: str | None, key, alg=ALG, exp_delta=timedelta(minutes=30), who=None) -> str:
    to = who or roles[as_role]
    c = dict(pl.swap_identity(CLAIMS, roles[_ref], to), exp=int((datetime.now(UTC) + exp_delta).timestamp()))
    return jwt.encode(c, key, algorithm=alg)


for role, spec in MAN["identities"].items():
    k = spec["kind"]
    if k == "anonymous":
        tokens[role] = None
    elif k == "minted":
        tokens[role] = mint(role, SECRET)
    elif k == "forged":
        tokens[role] = mint(spec["as"], "not-the-real-key-" + secrets.token_hex(16), alg="HS256")
    elif k == "expired":
        tokens[role] = mint(spec["as"], SECRET, exp_delta=timedelta(minutes=-5))
    elif k == "alg_none":
        tokens[role] = mint(spec["as"], None, alg="none")
    elif k == "deleted":
        tokens[role] = mint(None, SECRET, who={"user_id": str(uuid.uuid4()), "email": "ghost@example.com"})
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


def target_value(hint: str, target: str, schema: dict):
    return pl.target_value(hint, target, roles, seed_snapshot, MAN["ownership"], role_by_user_id, resolve(schema))


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


TARGETS = pl.effective_targets(MAN["targets"], MAN["ownership"], role_by_user_id, seed_snapshot)
results = []
t0 = time.time()
for op in ops:
    creds_op = op["body_kind"] == "form" and "password" in resolve(op["body_schema"]).get("properties", {})
    if op["unsupported"]:
        results.append({"op": op["key"], "unsupported": op["unsupported"]})
        continue
    targets = TARGETS if (op["path_params"] or creds_op) else ["-"]
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
                for p in op["params"]:
                    if p["in"] == "path":
                        url = url.replace("{" + p["name"] + "}", str(target_value(
                            MAN["param_hints"][p["name"]], target, p.get("schema", {}))))
                query = {p["name"]: gen_value(p["name"], p.get("schema", {}), caller)
                         for p in op["params"] if p["in"] == "query" and p.get("required")}
                kw = {"params": query}
                if op["body_kind"] == "json":
                    body = gen_body(op["body_schema"], caller)
                    if variant == "hostile":
                        victim = "user_b" if identity != "user_b" else "user_a"
                        body = pl.hostile(body, MAN["ownership"], roles[victim]["user_id"])
                    kw["json"] = body
                elif op["body_kind"] == "form":
                    if creds_op and target in roles:
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
                after = snapshot()
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
       "roles": {r: {"owns_items": len(v["items"]), "canaried_rows": canaried_rows[r], "flags": flags[r]}
                 for r, v in roles.items()},
       "public_operations": MAN["public_operations"], "results": results}
json.dump(out, open(args.out, "w"), indent=1)
print(f"[{args.tag}] {len(results)} probes in {out['elapsed_s']}s")
os._exit(0)
