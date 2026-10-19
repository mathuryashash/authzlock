import json
from types import SimpleNamespace as NS

from agent import onboard
from agent.tools import TEMPLATES, Tools

GOOD = {
    "api_prefix": "/api/v1",
    "identities": {"anonymous": {"kind": "anonymous"}, "user_a": {"kind": "login", "owns_items": 2},
                   "user_b": {"kind": "login", "owns_items": 1},
                   "superuser": {"kind": "login", "superuser": True, "owns_items": 1}},
    "privileged_identities": ["superuser"], "invalid_identities": ["anonymous"],
    "targets": ["user_a", "user_b", "nonexistent"],
    "ownership": {"user": {"owner": "self"}, "item": {"owner_column": "owner_id"}},
    "privilege_columns": {"user": ["is_superuser"]}, "ignored_columns": ["created_at"],
    "param_hints": {"id": "item_id", "user_id": "user_id"},
    "public_operations": ["POST /login/access-token"], "exceptions": [],
}


def test_good_manifest_validates():
    assert onboard.validate_manifest(GOOD) == []


def test_manifest_errors_are_specific():
    bad = json.loads(json.dumps(GOOD))
    del bad["ownership"]
    bad["param_hints"]["id"] = "whatever"
    bad["privileged_identities"] = ["ghost"]
    bad["identities"]["x"] = {"kind": "telepathy"}
    errs = "\n".join(onboard.validate_manifest(bad))
    for needle in ("ownership", "whatever", "ghost", "telepathy"):
        assert needle in errs


def test_seeder_must_parse_and_define_seed():
    assert onboard.validate_seeder("def seed(roles):\n    return {}\n") == []
    assert onboard.validate_seeder("def seed(:") and onboard.validate_seeder("x = 1\n")


def test_lock_template_is_fixed_and_reads_only_artifacts():
    argv = TEMPLATES["lock_artifacts"]
    assert all(isinstance(a, str) for a in argv)
    joined = " ".join(argv).replace("\\", "/")
    assert ".authzlock/artifacts/manifest.json" in joined and ".authzlock/artifacts/seeder.py" in joined


def tool_msg(name, args, id="c"):
    call = NS(id=id, type="function", function=NS(name=name, arguments=json.dumps(args)))
    return NS(choices=[NS(message=NS(content=None, tool_calls=[call], role="assistant"), finish_reason="tool_calls")])


class StubLLM:
    def __init__(self, script):
        self.script, self.requests = list(script), []

    def chat(self, model, messages, **kw):
        self.requests.append(messages)
        return self.script.pop(0)


def test_onboard_writes_artifacts_via_tools_and_reports_validation(tmp_path):
    (tmp_path / ".authzlock").mkdir()
    (tmp_path / ".authzlock" / "openapi.json").write_text("{}")
    llm = StubLLM([tool_msg("write_file", {"path": "manifest.json", "content": json.dumps(GOOD)}, "a"),
                   tool_msg("write_file", {"path": "seeder.py", "content": "def seed(roles):\n    return {}\n"}, "b"),
                   tool_msg("done", {"summary": "ok"}, "d")])
    res = onboard.onboard(tmp_path, llm, max_turns=5)
    assert res["status"] == "done" and res["errors"] == []
    art = tmp_path / ".authzlock" / "artifacts"
    assert json.loads((art / "manifest.json").read_text()) == GOOD
    user_prompt = llm.requests[0][1]["content"]
    assert "openapi.json" in user_prompt


def test_onboard_reports_missing_artifacts(tmp_path):
    (tmp_path / ".authzlock").mkdir()
    (tmp_path / ".authzlock" / "openapi.json").write_text("{}")
    res = onboard.onboard(tmp_path, StubLLM([tool_msg("done", {"summary": "lazy"})]), max_turns=2)
    assert any("manifest.json" in e for e in res["errors"]) and any("seeder.py" in e for e in res["errors"])


def test_manifest_field_types_are_checked():
    bad = json.loads(json.dumps(GOOD))
    bad["ignored_columns"] = {"user": ["created_at"]}  # agent run 1 wrote this; the worker wants a list
    bad["public_operations"] = "POST /login"
    errs = "\n".join(onboard.validate_manifest(bad))
    assert "ignored_columns" in errs and "public_operations" in errs
