import os

import pytest

from agent.cache import ArtifactCache, NoCachedArtifacts


def fake_generate(calls):
    def gen(out_dir):
        calls.append(1)
        (out_dir / "seeder.py").write_text("SEED = 1")
        (out_dir / "hints.json").write_text("{}")
    return gen


def test_artifact_cache_keyed_by_sha(tmp_path):
    cache, calls = ArtifactCache(tmp_path / "cache"), []
    d1 = cache.get_or_build("abc123", fake_generate(calls))
    d2 = cache.get_or_build("abc123", fake_generate(calls))
    assert calls == [1] and d1 == d2 and (d2 / "seeder.py").read_text() == "SEED = 1"
    cache.get_or_build("def456", fake_generate(calls))
    assert calls == [1, 1]


def test_failed_generation_is_not_cached(tmp_path):
    cache = ArtifactCache(tmp_path / "cache")

    def boom(out_dir):
        (out_dir / "half.py").write_text("x")
        raise RuntimeError("model died")
    with pytest.raises(RuntimeError):
        cache.get_or_build("abc999", boom)
    assert not cache.has("abc999")


def test_rejects_non_sha_keys(tmp_path):
    with pytest.raises(ValueError):
        ArtifactCache(tmp_path).get_or_build("../../etc", fake_generate([]))


def test_replay_mode_runs_without_api_keys(tmp_path, monkeypatch):
    for k in ("NEBIUS_API_KEY", "TAVILY_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    cache = ArtifactCache(tmp_path / "cache")
    cache.get_or_build("abc123", fake_generate([]))
    assert (cache.replay("abc123") / "seeder.py").exists()
    with pytest.raises(NoCachedArtifacts):
        cache.replay("ffff00")
    assert "NEBIUS_API_KEY" not in os.environ
