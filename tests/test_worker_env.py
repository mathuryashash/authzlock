import authzlock
from pathlib import Path


def test_worker_env_excludes_secrets(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "sk-should-not-leak")
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-should-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-should-not-leak")
    monkeypatch.setenv("DATABASE_URL", "postgresql://x/y")
    env = authzlock.worker_env()
    assert "NEBIUS_API_KEY" not in env
    assert "TAVILY_API_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert env["DATABASE_URL"] == "postgresql://x/y"
    assert env["TZ"] == "UTC"
    assert "PATH" in env


def test_worker_env_forces_utf8():  # Windows default cp1252 broke the template email reads (500s)
    assert authzlock.worker_env()["PYTHONUTF8"] == "1"


def test_run_worker_uses_absolute_python_for_relative_checkout(tmp_path, monkeypatch):
    # CI passes `--checkout wt_base`; the worker runs with cwd=backend, so a relative interpreter path breaks
    py = tmp_path / "wt" / ".venv" / "bin" / "python"
    py.parent.mkdir(parents=True)
    py.write_text("")
    (tmp_path / "wt" / "backend").mkdir()
    monkeypatch.chdir(tmp_path)
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        raise SystemExit("stop")

    monkeypatch.setattr(authzlock.subprocess, "run", fake_run)
    try:
        authzlock.run_worker(Path("wt"), "t", tmp_path / "o.json", 1025)
    except SystemExit:
        pass
    assert Path(seen["argv"][0]).is_absolute()


def test_worker_env_keeps_windows_home_and_app_profile(monkeypatch):  # asyncpg needs a home dir (D5)
    monkeypatch.setenv("USERPROFILE", "C:/Users/x")
    monkeypatch.setenv("AUTHZ_PROFILE", "apps/todos/profile.json")
    env = authzlock.worker_env()
    assert env["USERPROFILE"] == "C:/Users/x" and env["AUTHZ_PROFILE"] == "apps/todos/profile.json"


def test_worker_failure_leads_with_the_root_exception_not_shutdown_noise():
    err = ("INFO sql echo\nTraceback (most recent call last):\n  File \"seeder.py\", line 73, in _seed\n"
           "AttributeError: 'dict' object has no attribute 'password'\n"
           "Exception ignored in: <function _ProactorBasePipeTransport.__del__>\nTraceback (most recent call last):\n"
           "  File \"proactor_events.py\", line 116\nRuntimeError: Event loop is closed\n")
    assert authzlock.root_error(err) == "AttributeError: 'dict' object has no attribute 'password'"
    assert authzlock.root_error("harness invalid: seeder returned nothing for user_a\n") == \
        "harness invalid: seeder returned nothing for user_a"


def test_root_error_picks_the_exception_line_not_a_validation_detail():
    err = ("Traceback (most recent call last):\n  File \"x.py\", line 1\npydantic.error_wrappers.ValidationError: 2 "
           "validation errors for Settings\nSMTP_PORT\n  value is not a valid integer\nEMAILS_FROM_EMAIL\n")
    assert authzlock.root_error(err).startswith("pydantic.error_wrappers.ValidationError: 2 validation errors")
