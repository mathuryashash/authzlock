"""Sandboxes runner: the prove template runs in a Nebius Sandbox (ConTree) instead of a local worktree.
Fake client only; the live run is results/sandbox_run1/."""
import io
import json
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from contree_sdk.sdk.exceptions import ApiStatusCodeError, ForbiddenError

import sandbox_run as sr


def git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "t"
    (r / "backend/app").mkdir(parents=True)
    (r / "backend/app/main.py").write_text("x = 1\n")
    (r / "backend/tests").mkdir()
    (r / "backend/tests/conftest.py").write_text("")
    (r / "frontend").mkdir()
    (r / "frontend/big.js").write_text("ignored")
    git(r, "init", "-q"), git(r, "-c", "user.email=a@b", "-c", "user.name=a", "add", "-A")
    git(r, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "base")
    git(r, "branch", "-f", "base")
    return r


def test_tree_files_uploads_backend_at_ref_plus_test_and_env(repo, tmp_path):
    env = tmp_path / "target.env"
    env.write_bytes(b"SECRET_KEY=x\n")
    (repo / "backend/app/main.py").write_text("dirty working tree must not leak\n")
    f = sr.tree_files(repo, "base", b"def test_a(): pass\n", env)
    with tarfile.open(fileobj=io.BytesIO(f["/w/src.tar"])) as t:
        names = t.getnames()
        assert t.extractfile("backend/app/main.py").read().strip() == b"x = 1"  # autocrlf-agnostic; the committed ref, not the worktree
    assert not any(n.startswith("frontend") for n in names)
    assert f["/w/backend/tests/authz/test_regression.py"] == b"def test_a(): pass\n"
    assert f["/w/backend/tests/authz/__init__.py"] == b""
    assert f["/w/.env"] == b"SECRET_KEY=x\n" and "/w/" + sr.INNER_NAME in f


def test_parse_result_reads_marker_line():
    out = "noise\n" + sr.MARK + json.dumps({"junit": "<testsuite/>", "app_hash_before": "a"}) + "\n"
    assert sr.parse_result(out, "base")["junit"] == "<testsuite/>"
    bad = sr.parse_result("boom traceback", "head")
    assert bad["junit"] == "<testsuite/>" and bad["app_hash_after"] == "?" and "boom" in bad["stdout"]


def test_retry_only_transient_errors():
    calls, sleeps = [], []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise ApiStatusCodeError(status=500)
        return "ok"
    assert sr.retry(flaky, sleep=sleeps.append) == "ok" and sleeps == [2, 4]
    with pytest.raises(ForbiddenError):  # 403 is not transient: fail fast
        sr.retry(lambda: (_ for _ in ()).throw(ForbiddenError()), sleep=sleeps.append)


class FakeImage:
    def __init__(self, log, stdout=""):
        self.log, self.stdout = log, stdout

    def run(self, **kw):
        self.log.append(kw)
        out = sr.MARK + json.dumps({"junit": "<testsuite><testcase/></testsuite>", "app_hash_before": "h",
                                    "app_hash_after": "h", "stdout": ""})
        return NS(wait=lambda: NS(stdout=out, stderr=""))


def test_prove_sandbox_runs_base_and_head_offline_and_keyless(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "sk-should-not-leak")
    git(repo, "branch", "pr-x")
    art = tmp_path / "art"
    (art / "tests/authz").mkdir(parents=True)
    (art / "tests/authz/test_regression.py").write_text("def test_a(): pass\n")
    log = []
    monkeypatch.setattr(sr, "snapshot", lambda client, repo, ref, prof=None: FakeImage(log))
    nets = []
    monkeypatch.setattr(sr, "set_network", lambda client, on: nets.append(on))
    out = sr.prove_sandbox(art, {"scenario": "pr-x"}, repo, client=object(), env_file=tmp_path / "none.env")
    assert set(out) == {"base", "head"} and out["head"]["app_hash_after"] == "h"
    assert len(log) == 2 and nets == [False]
    for kw in log:
        assert not kw.get("env") and "sk-should-not-leak" not in json.dumps(
            {k: v for k, v in kw.items() if k != "files"})
        assert kw["disposable"] is True


def test_set_network_injects_networking_flag_into_spawn_body():
    sent = []
    api = NS(_build_request=lambda endpoint_info, data: sent.append(("orig", endpoint_info.path)),
             _client=NS(build_request=lambda m, url, json: sent.append((m, url, json))))
    client = NS(_api=api)
    ep = NS(method="post", path="/v1/instances", get_body_data_by_data=lambda d: {"command": "x"},
            get_path_by_data=lambda d: "/v1/instances")
    sr.set_network(client, False)
    api._build_request(endpoint_info=ep, data={})
    assert sent[-1] == ("POST", "/v1/instances", {"command": "x", "networking": {"enabled": False}})
    api._build_request(endpoint_info=NS(method="get", path="/v1/operations"), data={})
    assert sent[-1] == ("orig", "/v1/operations")


def test_agent_regress_picks_runner(monkeypatch):
    from agent import regress
    assert regress.pick_prove([]) is None  # local default: prove_scenario falls back to prove_local
    assert regress.pick_prove(["--runner", "local"]) is None
    p = regress.pick_prove(["--runner", "sandbox"])
    seen = []
    monkeypatch.setattr(sr, "prove_sandbox", lambda art, s, repo, client=None, prof=None: seen.append((art, s, repo)) or "r")
    assert p("art", {"scenario": "x"}, "repo") == "r" and seen == [("art", {"scenario": "x"}, Path("repo"))]
