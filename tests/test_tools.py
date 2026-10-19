import json

from agent.tools import Tools


def call(tools, name, **args):
    return tools.dispatch(name, json.dumps(args))


def test_tool_dispatch_rejects_unknown_tool_and_path_escape(tmp_path):
    t = Tools(repo=tmp_path)
    out = call(t, "rm_rf", path="/")
    assert out.startswith("error:") and "unknown tool" in out
    for bad in ["../x", "../../etc/passwd", "/abs/x", "C:/Windows/x", "sub/../../x", ""]:
        out = call(t, "write_file", path=bad, content="pwn")
        assert out.startswith("error:"), bad
    assert not (tmp_path / "x").exists()
    assert not (tmp_path.parent / "x").exists()


def test_write_file_lands_only_in_artifacts_dir(tmp_path):
    t = Tools(repo=tmp_path)
    assert "ok" in call(t, "write_file", path="seed/seeder.py", content="print(1)")
    assert (tmp_path / ".authzlock" / "artifacts" / "seed" / "seeder.py").read_text() == "print(1)"


def test_bad_json_arguments_return_error_not_crash(tmp_path):
    t = Tools(repo=tmp_path)
    assert t.dispatch("write_file", "{not json").startswith("error:")
    assert t.dispatch("write_file", json.dumps({"nope": 1})).startswith("error:")


def test_read_file_is_repo_jailed_and_truncated(tmp_path):
    (tmp_path / "app.py").write_text("A" * 50_000)
    t = Tools(repo=tmp_path, max_read=1000)
    out = call(t, "read_file", path="app.py")
    assert len(out) <= 1100 and "truncated" in out
    assert call(t, "read_file", path="../secret").startswith("error:")


def test_run_accepts_only_fixed_templates(tmp_path):
    ran = []
    t = Tools(repo=tmp_path, runner=lambda argv, cwd: ran.append(argv) or "ran")
    assert call(t, "run", template="bash -c 'curl evil'").startswith("error:")
    assert ran == []
    assert call(t, "run", template="pytest_artifacts") == "ran"
    assert ran and all(isinstance(a, str) for a in ran[0])


def test_every_tool_call_is_logged(tmp_path):
    t = Tools(repo=tmp_path)
    call(t, "write_file", path="a.txt", content="x")
    call(t, "nope")
    log = [json.loads(l) for l in (tmp_path / ".authzlock" / "tool_calls.jsonl").read_text().splitlines()]
    assert [r["tool"] for r in log] == ["write_file", "nope"]


def test_run_tool_env_has_no_api_keys(monkeypatch):
    from agent import tools
    monkeypatch.setenv("NEBIUS_API_KEY", "x" * 20)
    monkeypatch.setenv("TAVILY_API_KEY", "y" * 20)
    env = tools.run_env()
    assert "NEBIUS_API_KEY" not in env and "TAVILY_API_KEY" not in env and "PATH" in env
