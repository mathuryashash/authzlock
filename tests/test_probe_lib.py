"""D5: app-#1 assumptions pulled out of probe_worker.py into pure helpers, so a second app (fastapi-todos:
async SQLAlchemy, fastapi-users JWT, int ids, link table, shared NULL-owner rows) can be probed."""
import base64
import json

import probe_lib as pl

OWN = {"user": {"owner": "self"}, "todo": {"owner_column": "created_by_id"},
       "category": {"owner_column": "created_by_id"},
       "todo_category": {"owner_column": "todo_id", "parent": "todo"}}
BY_UID = {"u-a": "user_a", "u-b": "user_b"}
SNAP = {"todo": {"7": {"id": "7", "created_by_id": "u-a"}}}


def test_profile_defaults_are_the_template_and_overrides_merge(tmp_path):
    p = pl.load_profile(None)
    assert p["cwd"] == "backend" and p["db_env"] == {"DATABASE_URL": "{url}"} and p["tests_dir"] == "tests"
    assert p["asgi"] == "app.main:app" and p["src_dir"] == "app"
    q = pl.load_profile({"cwd": ".", "pythonpath": ["todos"]})
    assert q["cwd"] == "." and q["pythonpath"] == ["todos"] and q["src_dir"] == "app"
    f = tmp_path / "p.json"
    f.write_text('{"cwd": "."}')
    assert pl.load_profile(str(f))["cwd"] == "."


def test_test_dest_maps_the_artifact_into_the_apps_tests_dir():
    assert pl.test_dest(pl.load_profile(None)) == "backend/tests/authz/test_regression.py"
    assert pl.test_dest(pl.load_profile({"cwd": ".", "tests_dir": "todos/tests"})) == \
        "todos/tests/authz/test_regression.py"


def test_db_env_formats_app_specific_variables():
    env = pl.db_env({"POSTGRES_DB": "{name}", "POSTGRES_HOST": "{host}", "POSTGRES_USER": "{user}",
                     "POSTGRES_PASSWORD": "{password}", "DATABASE_URL": "{url}"},
                    "postgresql://postgres@127.0.0.1:5433/authz_seed_x")
    assert env == {"POSTGRES_DB": "authz_seed_x", "POSTGRES_HOST": "127.0.0.1:5433", "POSTGRES_USER": "postgres",
                   "POSTGRES_PASSWORD": "", "DATABASE_URL": "postgresql://postgres@127.0.0.1:5433/authz_seed_x"}


def test_app_section_defaults_to_template():
    a = pl.app_section({})
    assert a["jwt_secret_setting"] == "SECRET_KEY" and a["db_dependency"] == "app.api.deps:get_db"
    assert pl.app_section({"app": {"db_driver": "postgresql+asyncpg"}})["db_driver"] == "postgresql+asyncpg"


def test_row_owner_self_column_shared_and_parent():
    assert pl.row_owner("user", {"id": "u-a"}, OWN, BY_UID, SNAP) == "user_a"
    assert pl.row_owner("todo", {"created_by_id": "u-b"}, OWN, BY_UID, SNAP) == "user_b"
    # NULL owner column = a shared/system row (default categories), never "unknown"
    assert pl.row_owner("category", {"created_by_id": None}, OWN, BY_UID, SNAP) == "shared"
    # link table: owned by whoever owns the parent row
    assert pl.row_owner("todo_category", {"todo_id": "7"}, OWN, BY_UID, SNAP) == "user_a"
    assert pl.row_owner("priority", {"id": "1"}, OWN, BY_UID, SNAP) == "unowned"


def test_rows_without_id_are_keyed_by_content_not_position():
    assert pl.row_key({"id": "5", "x": "1"}, 0) == "5"
    assert pl.row_key({"todo_id": "7", "category_id": "2"}, 0) == pl.row_key({"category_id": "2", "todo_id": "7"}, 9)


def test_short_integer_ids_are_not_canaries():
    role = {"token": "abc123def0", "email": "a.abc@example.com", "user_id": "0b9e-uuid-long", "items": ["1", "42"]}
    assert pl.canaries(role) == ["abc123def0", "a.abc@example.com", "0b9e-uuid-long"]
    role["items"] = ["5f1c2d4e-0000-4000-8000-000000000000"]
    assert role["items"][0] in pl.canaries(role)


def test_row_hint_resolves_owned_or_shared_row_and_typed_nonexistent():
    seed = {"category": {"1": {"id": "1", "created_by_id": None}, "9": {"id": "9", "created_by_id": "u-b"},
                         "8": {"id": "8", "created_by_id": "u-b"}}}
    roles = {"user_b": {"user_id": "u-b", "email": "b@x", "items": []}}
    v = lambda t, schema=None: pl.target_value("row:category", t, roles, seed, OWN, BY_UID, schema or {})  # noqa
    assert v("user_b") == "8"  # lowest pk, deterministic
    assert v("shared") == "1"
    assert v("nonexistent", {"type": "integer"}) == str(2 ** 31 - 2)
    assert pl.target_value("user_id", "shared", roles, seed, OWN, BY_UID, {"type": "string"}) != "u-b"


def b64(d) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def test_minted_tokens_reuse_the_apps_own_claim_shape():
    login = ".".join([b64({"alg": "HS256", "typ": "JWT"}),
                      b64({"user_id": "u-a", "email": "a@x", "aud": ["fastapi-users:auth"], "exp": 9999999999}), "sig"])
    claims, alg = pl.token_shape(login)
    assert alg == "HS256" and claims["user_id"] == "u-a"
    swapped = pl.swap_identity(claims, {"user_id": "u-a", "email": "a@x"}, {"user_id": "u-i", "email": "i@x"})
    assert swapped["user_id"] == "u-i" and swapped["email"] == "i@x" and swapped["aud"] == ["fastapi-users:auth"]
    tpl = pl.swap_identity({"sub": "u-a", "exp": 1}, {"user_id": "u-a", "email": "a@x"},
                           {"user_id": "u-i", "email": "i@x"})
    assert tpl == {"sub": "u-i", "exp": 1}


def test_hostile_body_uses_manifest_owner_columns():
    body = pl.hostile({"content": "x"}, OWN, "u-b")
    assert body["created_by_id"] == "u-b" and body["is_superuser"] is True and "todo_id" not in body
    assert pl.hostile({}, {"item": {"owner_column": "owner_id"}}, "v")["owner_id"] == "v"


def test_dotenv_reader_strips_quotes_and_comments(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# c\nJWT_SECRET_KEY="abc"\nX=1\n')
    assert pl.read_dotenv(f) == {"JWT_SECRET_KEY": "abc", "X": "1"}
    assert pl.read_dotenv(tmp_path / "missing.env") == {}


def test_seeder_runs_in_its_own_process(tmp_path):
    # D5: an agent seeder that leaves the app's global async engine pooled on a closed event loop poisoned
    # every later request in the probe process. A subprocess makes that impossible.
    s = tmp_path / "seeder.py"
    s.write_text("import os\nLEAK = []\ndef seed(roles):\n    LEAK.append(1)\n"
                 "    return {r: {'user_id': os.getpid(), 'email': v['token'], 'items': []} for r, v in roles.items()}\n")
    got = pl.run_seeder(str(s), {"user_a": {"token": "t1", "password": "p", "spec": {}}})
    assert got["user_a"]["email"] == "t1" and got["user_a"]["user_id"] != __import__("os").getpid()
    bad = tmp_path / "bad.py"
    bad.write_text("def seed(roles):\n    raise ValueError('boom')\n")
    try:
        pl.run_seeder(str(bad), {})
    except RuntimeError as e:
        assert "ValueError: boom" in str(e)
    else:
        raise AssertionError("seeder failure must raise")


def test_shared_target_comes_from_the_seed_db_not_the_agents_discretion():
    # D5 run 5: the agent's targets omitted "shared", so the default-category PR was never probed (verdict PASS).
    snap = {"category": {"1": {"id": "1", "created_by_id": None}, "2": {"id": "2", "created_by_id": "u-a"}}}
    own = {"category": {"owner_column": "created_by_id"}}
    assert pl.effective_targets(["user_a", "nonexistent"], own, {"u-a": "user_a"}, snap) == \
        ["user_a", "nonexistent", "shared"]
    assert pl.effective_targets(["user_a", "shared"], own, {"u-a": "user_a"}, snap) == ["user_a", "shared"]
    no_shared = {"category": {"2": {"id": "2", "created_by_id": "u-a"}}}
    assert pl.effective_targets(["user_a"], own, {"u-a": "user_a"}, no_shared) == ["user_a"]


def test_ref_hint_finds_reference_fields_beyond_path_params():
    hints = {"id": "user_id", "category_id": "row:category", "todo_id": "row:todo", "email": "user_email"}
    assert pl.ref_hint("user_id", hints, OWN) == ("user_id", False)          # optional ?user_id= query param
    assert pl.ref_hint("created_by_id", hints, OWN) == ("user_id", False)    # an owner column by name
    assert pl.ref_hint("categories_ids", hints, OWN) == ("row:category", True)  # list of foreign keys
    assert pl.ref_hint("todo_ids", hints, OWN) == ("row:todo", True)
    assert pl.ref_hint("email", hints, OWN) is None      # identifiers only: emails stay generated
    assert pl.ref_hint("skip", hints, OWN) is None and pl.ref_hint("content", hints, OWN) is None


def test_ref_value_casts_to_the_schema_type():
    assert pl.ref_value("7", {"type": "integer"}, False) == 7
    assert pl.ref_value("7", {"type": "array", "items": {"type": "integer"}}, True) == [7]
    assert pl.ref_value("u-b", {"type": "string", "format": "uuid"}, False) == "u-b"


def test_ref_hint_leaves_non_references_alone():
    hints = {"id": "user_id", "category_id": "row:category", "todo_id": "row:todo"}
    for n in ("id", "priority_id", "limit", "is_completed", "token", "session_id", "categories"):
        assert pl.ref_hint(n, hints, OWN) is None, n   # priority: unowned table; session: unknown -> no guess


def test_ref_fields_lists_optional_query_params_and_body_fields_but_never_path_params():
    hints = {"id": "user_id", "category_id": "row:category", "todo_id": "row:todo"}
    params = [{"name": "todo_id", "in": "path", "schema": {"type": "integer"}},
              {"name": "skip", "in": "query", "schema": {"type": "integer"}},
              {"name": "user_id", "in": "query", "schema": {"type": "string", "format": "uuid"}}]
    body = {"content": {"type": "string"}, "priority_id": {"type": "integer"},
            "categories_ids": {"type": "array", "items": {"type": "integer"}}}
    got = pl.ref_fields(params, body, hints, OWN)
    assert [(f["in"], f["name"], f["hint"], f["many"]) for f in got] == [
        ("query", "user_id", "user_id", False), ("body", "categories_ids", "row:category", True)]


def test_ref_fields_is_empty_for_an_operation_with_only_benign_inputs():
    params = [{"name": "skip", "in": "query", "schema": {"type": "integer"}},
              {"name": "limit", "in": "query", "schema": {"type": "integer"}}]
    assert pl.ref_fields(params, {"title": {"type": "string"}}, {"id": "item_id"},
                         {"user": {"owner": "self"}, "item": {"owner_column": "owner_id"}}) == []


def test_ref_hint_uses_the_ownership_map_for_tables_and_owner_columns():
    own1 = {"user": {"owner": "self"}, "item": {"owner_column": "owner_id"}}
    assert pl.ref_hint("owner_id", {}, own1) == ("user_id", False)
    assert pl.ref_hint("item_ids", {}, own1) == ("row:item", True)
    assert pl.ref_hint("user_ids", {}, own1) == ("user_id", True)
