"""Fixed command template body (security #4/#5): run ONE regression test file on ONE ref of the target.

  <target venv python> regress_run.py <target repo> <ref> <test file> <out.json>

Deterministic, no LLM, no API keys (the caller passes a key-free env). Makes a detached worktree of <ref>,
copies the test to backend/tests/authz/, migrates a fresh DB on AUTHZ_PG, runs pytest with --junitxml and
writes {junit, app_hash_before, app_hash_after, stdout} to <out.json>. Always cleans up.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import psycopg

HERE = Path(__file__).resolve().parent


def app_hash(backend: Path) -> str:
    h = hashlib.sha256()
    for p in sorted((backend / "app").rglob("*.py")):
        h.update(p.relative_to(backend).as_posix().encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def main(repo: Path, ref: str, test: Path, out: Path) -> None:
    pg = os.environ.get("AUTHZ_PG", "postgresql://postgres@127.0.0.1:5433/postgres")
    tree = Path(tempfile.mkdtemp(prefix="authz_rt_"))
    db = f"authz_rt_{os.getpid()}"
    admin = psycopg.connect(pg, autocommit=True)
    try:
        subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(tree / "wt"), ref], check=True,
                       capture_output=True)
        wt = tree / "wt"
        shutil.copy(HERE / "target.env", wt / ".env")
        backend = wt / "backend"
        tdir = backend / "tests" / "authz"
        tdir.mkdir(parents=True, exist_ok=True)
        (tdir / "__init__.py").write_text("")
        shutil.copy(test, tdir / "test_regression.py")
        admin.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
        admin.execute(f'CREATE DATABASE "{db}"')
        env = dict(os.environ, DATABASE_URL=pg.rsplit("/", 1)[0] + f"/{db}",
                   PYTHONUTF8="1", TZ="UTC")
        before = app_hash(backend)
        mig = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=backend, env=env,
                             capture_output=True, text=True)
        junit = tree / "junit.xml"
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml", str(junit),
                            "tests/authz/test_regression.py"], cwd=backend, env=env, capture_output=True, text=True,
                           timeout=300)
        res = {"ref": ref, "junit": junit.read_text() if junit.exists() else "<testsuite/>",
               "app_hash_before": before, "app_hash_after": app_hash(backend),
               "stdout": (mig.stderr[-800:] if mig.returncode else "") + (p.stdout + p.stderr)[-3000:]}
    finally:
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(tree / "wt")], capture_output=True)
        admin.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
        admin.close()
        shutil.rmtree(tree, ignore_errors=True)
    Path(out).write_text(json.dumps(res))


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve(), Path(sys.argv[4]))
