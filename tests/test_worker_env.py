import authzlock


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
