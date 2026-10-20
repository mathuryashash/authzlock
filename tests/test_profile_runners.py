"""D5: the prove template (regress_run.py local, sandbox_run.py in Sandboxes) follows the app profile, so app #2's
tests land in todos/tests/authz/ with cwd = checkout root, PYTHONPATH=todos and POSTGRES_* env vars."""
import io
import json
import subprocess
import tarfile

import probe_lib as pl
import regress_run
import sandbox_run as sr

TODOS = pl.load_profile({"cwd": ".", "pythonpath": ["todos"], "src_dir": "todos/app", "tests_dir": "todos/tests",
                         "db_env": {"POSTGRES_DB": "{name}", "POSTGRES_HOST": "{host}"}, "archive": [],
                         "sandbox": {"image": "python:3.9-slim", "dep_files": ["requirements.txt"],
                                     "deps": "pip install -q -r /dep/requirements.txt pytest==7.4.4"}})


def test_app_hash_follows_src_dir(tmp_path):
    (tmp_path / "todos/app").mkdir(parents=True)
    (tmp_path / "todos/app/x.py").write_text("a = 1\n")
    h = regress_run.app_hash(tmp_path, "todos/app")
    (tmp_path / "todos/app/x.py").write_text("a = 2\n")
    assert regress_run.app_hash(tmp_path, "todos/app") != h
    assert regress_run.app_hash(tmp_path / "todos", "app") == regress_run.app_hash(tmp_path, "todos/app")


def test_run_env_sets_app_db_vars_and_pythonpath(tmp_path):
    env = regress_run.run_env(TODOS, "postgresql://postgres@127.0.0.1:5433/postgres", "authz_rt_1", tmp_path)
    assert env["POSTGRES_DB"] == "authz_rt_1" and env["POSTGRES_HOST"] == "127.0.0.1:5433"
    assert env["PYTHONPATH"] == str(tmp_path / "todos")
    tpl = regress_run.run_env(pl.load_profile(None), "postgresql://postgres@h:1/postgres", "d", tmp_path)
    assert tpl["DATABASE_URL"] == "postgresql://postgres@h:1/d" and "PYTHONPATH" not in tpl


def git(repo, *a):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=a@b", "-c", "user.name=a", *a], check=True,
                   capture_output=True)


def test_sandbox_tree_files_and_recipe_follow_profile(tmp_path):
    r = tmp_path / "t"
    (r / "todos/app").mkdir(parents=True)
    (r / "todos/app/main.py").write_text("x = 1\n")
    (r / "requirements.txt").write_text("fastapi==0.85.0\n")
    (r / "alembic.ini").write_text("[alembic]\n")
    git(r, "init", "-q"), git(r, "add", "-A"), git(r, "commit", "-qm", "b"), git(r, "branch", "-f", "base")
    f = sr.tree_files(r, "base", b"def test_a(): pass\n", tmp_path / "none.env", TODOS)
    with tarfile.open(fileobj=io.BytesIO(f["/w/src.tar"])) as t:
        assert {"alembic.ini", "todos/app/main.py"} <= set(t.getnames())
    assert f["/w/todos/tests/authz/test_regression.py"] == b"def test_a(): pass\n"
    assert f["/w/todos/tests/authz/__init__.py"] == b""
    assert json.loads(f["/w/profile.json"])["cwd"] == "." and "/w/probe_lib.py" in f
    image, build = sr.recipe(TODOS)
    assert image == "python:3.9-slim" and "pip install -q -r /dep/requirements.txt" in build
    assert "uv export" not in build and "initdb" in build
    assert set(sr.dep_files(r, "base", TODOS)) == {"/dep/requirements.txt", "/dep/shmshim.c"}
    t_image, t_build = sr.recipe(pl.load_profile(None))
    assert t_image == "python:3.14-slim" and "uv export" in t_build


def test_base_image_is_imported_once_when_the_registry_lacks_it():
    # D5: python:3.9-slim was not yet imported in the project ("Image with tag 'tag:python:3.9-slim' not found").
    calls = []

    class Imgs:
        def use(self, tag, strict=False):
            calls.append(("use", tag))
            raise sr_missing()

        def pull(self, ref, new_tag=None, timeout=None):
            calls.append(("pull", ref, new_tag))
            return "IMG"

    class C:
        images = Imgs()

    from contree_sdk.sdk.exceptions import ContreeError

    def sr_missing():
        return ContreeError()
    assert sr.base_image(C(), "python:3.9-slim") == "IMG"
    assert calls == [("use", "python:3.9-slim"), ("pull", "docker.io/library/python:3.9-slim", "python:3.9-slim")]
