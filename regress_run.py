"""Fixed command template body (security #4/#5): run ONE regression test file on ONE ref of the target.

  <target venv python> regress_run.py <target repo> <ref> <test file> <out.json>

Deterministic, no LLM, no API keys (the caller passes a key-free env). Makes a detached worktree of <ref>,
copies the test to <cwd>/<tests_dir>/authz/ (app profile, env AUTHZ_PROFILE; default = the template), migrates a
fresh DB on AUTHZ_PG, runs pytest with --junitxml and writes {junit, app_hash_before, app_hash_after, stdout} to
<out.json>. Always cleans up.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import probe_lib as pl  # noqa: E402


def app_hash(cwd: Path, src_dir: str = "app") -> str:
    h = hashlib.sha256()
    for p in sorted((cwd / src_dir).rglob("*.py")):
        h.update(p.relative_to(cwd / src_dir).as_posix().encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def run_env(prof: dict, pg: str, db: str, cwd: Path) -> dict:
    env = dict(os.environ, **pl.db_env(prof["db_env"], pg.rsplit("/", 1)[0] + f"/{db}"), PYTHONUTF8="1", TZ="UTC")
    if prof["pythonpath"]:
        env["PYTHONPATH"] = os.pathsep.join(str(Path(cwd, p)) for p in prof["pythonpath"])
    return env


def run_pytest(cwd: Path, prof: dict, env: dict, junit: Path) -> dict:
    """Shared by the local and the Sandboxes runner: migrate, pytest --junitxml, hash the app source around it."""
    before = app_hash(cwd, prof["src_dir"])
    mig = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=cwd, env=env,
                         capture_output=True, text=True)
    test = Path(prof["tests_dir"], "authz", "test_regression.py").as_posix()
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml", str(junit), test],
                       cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
    return {"junit": junit.read_text() if junit.exists() else "<testsuite/>",
            "app_hash_before": before, "app_hash_after": app_hash(cwd, prof["src_dir"]),
            "stdout": (mig.stderr[-800:] if mig.returncode else "") + (p.stdout + p.stderr)[-3000:]}


def main(repo: Path, ref: str, test: Path, out: Path) -> None:
    import psycopg
    prof = pl.profile()
    pg = os.environ.get("AUTHZ_PG", "postgresql://postgres@127.0.0.1:5433/postgres")
    tree = Path(tempfile.mkdtemp(prefix="authz_rt_"))
    db = f"authz_rt_{os.getpid()}"
    admin = psycopg.connect(pg, autocommit=True)
    try:
        subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(tree / "wt"), ref], check=True,
                       capture_output=True)
        wt = tree / "wt"
        shutil.copy(HERE / prof["env_file"], wt / ".env")
        cwd = wt / prof["cwd"]
        tdir = cwd / prof["tests_dir"] / "authz"
        tdir.mkdir(parents=True, exist_ok=True)
        (tdir / "__init__.py").write_text("")
        shutil.copy(test, tdir / "test_regression.py")
        admin.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
        admin.execute(f'CREATE DATABASE "{db}"')
        res = dict(run_pytest(cwd, prof, run_env(prof, pg, db, cwd), tree / "junit.xml"), ref=ref)
    finally:
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(tree / "wt")], capture_output=True)
        admin.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
        admin.close()
        shutil.rmtree(tree, ignore_errors=True)
    Path(out).write_text(json.dumps(res))


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve(), Path(sys.argv[4]))
