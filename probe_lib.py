"""Pure helpers for probe_worker.py: everything that used to assume app #1 (the template) lives here, behind an
app *profile* (how to boot/migrate/test the app: infra, host-side) and the manifest's optional "app" section
(how the app wires its DB session and JWT secret: written by the onboarding agent). Defaults = the template.
Imported by the worker inside the TARGET's venv (py3.9+), so stdlib only.
"""
from __future__ import annotations

import base64
import json
import re
import os
import uuid
from pathlib import Path
from urllib.parse import urlsplit

PROFILE_DEFAULTS = {
    "cwd": "backend",            # where alembic/pytest/app imports run, relative to the checkout
    "pythonpath": [],            # extra sys.path entries, relative to cwd
    "asgi": "app.main:app",      # module:attr of the ASGI app
    "src_dir": "app",            # app source (hashed by the proof), relative to cwd
    "tests_dir": "tests",        # the app's pytest dir (conftest), relative to cwd
    "db_env": {"DATABASE_URL": "{url}"},  # env vars that point the app at a database
    "env_file": "target.env",    # copied to <checkout>/.env; relative to the authzlock repo
    "patches_dir": "scenarios",
    "archive": ["backend"],      # paths uploaded to Sandboxes (git archive), [] = whole tree
    "sandbox": None,             # None = sandbox_run's template recipe
}
APP_DEFAULTS = {"db_dependency": "app.api.deps:get_db", "session_class": "sqlmodel:Session",
                "db_driver": "postgresql+psycopg", "jwt_secret_setting": "SECRET_KEY"}


def load_profile(p=None) -> dict:
    """p: None (template), a dict, or a path to a JSON file. AUTHZ_PROFILE env is read by profile()."""
    if isinstance(p, (str, Path)):
        p = json.loads(Path(p).read_text())
    return dict(PROFILE_DEFAULTS, **(p or {}))


def profile() -> dict:
    return load_profile(os.environ.get("AUTHZ_PROFILE") or None)


def test_dest(prof: dict) -> str:
    """Checkout-relative path the agent's tests/authz/test_regression.py is copied to."""
    return Path(prof["cwd"], prof["tests_dir"], "authz", "test_regression.py").as_posix().lstrip("./")


def app_section(man: dict) -> dict:
    return dict(APP_DEFAULTS, **man.get("app", {}))


def db_env(template: dict, url: str) -> dict:
    u = urlsplit(url)
    host = u.hostname + (f":{u.port}" if u.port else "")
    vals = {"url": url, "name": u.path.lstrip("/"), "host": host, "user": u.username or "",
            "password": u.password or ""}
    return {k: v.format(**vals) for k, v in template.items()}


def read_dotenv(path: Path) -> dict:
    out = {}
    if Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def row_key(row: dict, i: int) -> str:
    """Primary key for diffing: the id column, else the full row (link tables have no id; position shifts)."""
    return str(row["id"]) if row.get("id") is not None else json.dumps(row, sort_keys=True)


def row_owner(table: str, row: dict, own: dict, by_uid: dict, snap: dict) -> str:
    o = own.get(table, {})
    if o.get("owner") == "self":
        return by_uid.get(row.get("id"), "new")
    col = o.get("owner_column")
    if not col:
        return "unowned"
    if row.get(col) is None:
        return "shared"  # NULL owner = a system row every user sees (e.g. default categories)
    if o.get("parent"):  # link table: owned by whoever owns the parent row
        parent = snap.get(o["parent"], {}).get(str(row[col]))
        return row_owner(o["parent"], parent, own, by_uid, snap) if parent else "unknown"
    return by_uid.get(row.get(col), "unknown")


def canaries(role: dict) -> list:
    # ponytail: short ids (ints like "1") match everywhere; only long ids (uuids) are canaries.
    return [role["token"], role["email"], role["user_id"], *[i for i in role["items"] if len(str(i)) >= 8]]


def nonexistent(schema: dict, hint: str) -> str:
    if hint == "user_email":
        return f"ghost.{uuid.uuid4().hex[:6]}@example.com"
    return str(2 ** 31 - 2) if schema.get("type") == "integer" else str(uuid.uuid4())


def target_value(hint: str, target: str, roles: dict, seed: dict, own: dict, by_uid: dict, schema: dict) -> str:
    """hint: item_id | user_id | user_email | row:<table> (the target's lowest-pk row in that table, from the
    seed DB; target 'shared' = a NULL-owner row)."""
    if target == "nonexistent" or (target == "shared" and not hint.startswith("row:")):
        return nonexistent(schema, hint)
    if hint.startswith("row:"):
        t = hint[4:]
        rows = sorted(seed.get(t, {}).items(), key=lambda kv: (len(kv[0]), kv[0]))
        hit = next((k for k, r in rows if row_owner(t, r, own, by_uid, seed) == target), None)
        return hit if hit is not None else nonexistent(schema, hint)
    r = roles[target]
    return {"item_id": (r["items"] or [str(uuid.uuid4())])[0], "user_id": r["user_id"],
            "user_email": r["email"]}[hint]


def hostile(body: dict, own: dict, victim_uid: str) -> dict:
    cols = {o["owner_column"] for o in own.values() if o.get("owner_column") and not o.get("parent")}
    return dict(body, is_superuser=True, is_active=True, **{c: victim_uid for c in cols})


def _b64json(s: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def token_shape(token: str):
    """Claims + alg of a REAL login token: minted/forged tokens copy the app's own claim layout."""
    h, c, _ = token.split(".")
    return _b64json(c), _b64json(h).get("alg", "HS256")


def swap_identity(claims: dict, frm: dict, to: dict) -> dict:
    m = {frm["user_id"]: to["user_id"], frm["email"]: to["email"]}
    return {k: m.get(v, v) if isinstance(v, str) else v for k, v in claims.items()}


SEED_MAIN = r"""import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("authz_seeder", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
out = m.seed(json.loads(sys.stdin.read()))
sys.stdout.write("\nAUTHZ_SEED " + json.dumps(out, default=str) + "\n")
"""


def run_seeder(path: str, roles: dict, cwd=None, env=None) -> dict:
    """Run the (LLM-written) seeder in its own process: its engines, event loops and globals die with it."""
    import subprocess
    import sys
    p = subprocess.run([sys.executable, "-c", SEED_MAIN, path], input=json.dumps(roles), capture_output=True,
                       text=True, cwd=cwd, env=env, timeout=600)
    line = next((x for x in reversed(p.stdout.splitlines()) if x.startswith("AUTHZ_SEED ")), None)
    if p.returncode != 0 or line is None:
        tb = [x for x in p.stderr.splitlines() if re.match(r"^[\w.]*(Error|Exception):", x)]
        raise RuntimeError(f"seeder failed (exit {p.returncode}): {tb[-1] if tb else ''}\n{p.stderr[-2500:]}")
    return json.loads(line[len("AUTHZ_SEED "):])


def effective_targets(targets: list, own: dict, by_uid: dict, snap: dict) -> list:
    """Manifest targets, plus "shared" whenever the seed DB holds NULL-owner rows in an owned table: whether
    non-owners may mutate those is exactly the question a PR can silently change, so it is always probed."""
    has_shared = any(row_owner(t, r, own, by_uid, snap) == "shared" for t in own for r in snap.get(t, {}).values())
    return list(targets) + (["shared"] if has_shared and "shared" not in targets else [])


# ---------------------------------------------------------------- foreign-reference variant
REF_HINTS = ("item_id", "user_id")  # hint kinds that name a principal or one of its rows (never emails)


def _singular(w: str) -> str:
    return w[:-3] + "y" if w.endswith("ies") else w[:-1] if w.endswith("s") and not w.endswith("ss") else w


def ref_hint(name: str, hints: dict, own: dict):
    """(hint, many) when a query param / body field NAME looks like a reference to someone's resource, else None.
    Generic, from the manifest only: `<x>_id` / `<x>_ids` where <x> has a param hint (category_id -> row:category),
    is an owned table (item_ids -> row:item), is the user table (user_id), or the name is an owner column
    (owner_id, created_by_id). Unowned tables (priority_id) and unknown names are left alone: no guessing."""
    if name.endswith("_ids"):
        stem, many = name[:-4], True
    elif name.endswith("_id"):
        stem, many = name[:-3], False
    else:
        return None
    if not stem:
        return None
    owner_cols = {o["owner_column"] for o in own.values() if o.get("owner_column") and not o.get("parent")}
    if not many and name in owner_cols:
        return "user_id", many
    for s in dict.fromkeys((stem, _singular(stem))):
        h = hints.get(s + "_id")
        if h and (h in REF_HINTS or h.startswith("row:")):
            return h, many
        o = own.get(s)
        if o and o.get("owner") == "self":
            return "user_id", many
        if o and o.get("owner_column") and not o.get("parent"):
            return "row:" + s, many
    if _singular(stem) + "_id" in owner_cols:  # owner_ids
        return "user_id", many
    return None


def ref_fields(params: list, body_props: dict, hints: dict, own: dict) -> list:
    """Every query param (required or not) and body field of an operation that ref_hint() recognises.
    Path params are excluded: they are already probed per target."""
    out = []
    for p in params:
        if p.get("in") == "query" and ref_hint(p["name"], hints, own):
            h, many = ref_hint(p["name"], hints, own)
            out.append({"in": "query", "name": p["name"], "hint": h, "many": many, "schema": p.get("schema", {})})
    for n, sch in (body_props or {}).items():
        if ref_hint(n, hints, own):
            h, many = ref_hint(n, hints, own)
            out.append({"in": "body", "name": n, "hint": h, "many": many, "schema": sch})
    return out


def ref_value(raw: str, schema: dict, many: bool):
    """The victim's id cast to the field's (resolved) schema type; a list when the field is a list."""
    if many or schema.get("type") == "array":
        item = schema.get("items", {}) if schema.get("type") == "array" else schema
        return [ref_value(raw, item, False)]
    return int(raw) if schema.get("type") == "integer" and str(raw).lstrip("-").isdigit() else raw
