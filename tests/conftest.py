import pytest


@pytest.fixture(autouse=True)
def _template_profile(monkeypatch):  # hermetic: a shell's AUTHZ_PROFILE (app #2) must not leak into unit tests
    monkeypatch.delenv("AUTHZ_PROFILE", raising=False)
