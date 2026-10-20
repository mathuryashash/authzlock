"""Nebius Sandboxes (ConTree) backend for the fixed `prove` template: same contract as regress_run.py, run in a VM.

  python sandbox_run.py <target repo> <diffs dir> <tests dir> <out dir> [--runner sandbox|local]

Re-proves already-written tests (<tests dir>/<scenario>.test_regression.py) on base and head, no LLM.
Host side: one snapshot per (app, base SHA) = python:3.14-slim + Postgres + the app's locked deps, built once with
network ON and reused by tag. Every proof run is disposable, has NO guest network (networking.enabled=false) and no
env= at all: the API key stays on the host. `git archive <ref> <profile archive paths>` (committed tree only) + the test + target.env
are uploaded via files=; the guest starts Postgres, runs this file with --inner and prints one MARK+json line.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import probe_lib as pl  # noqa: E402
INNER_NAME = "sandbox_run.py"
MARK = "AUTHZLOCK_RESULT "
TEST = "tests/authz/test_regression.py"
GUEST_PG = "postgresql://postgres@127.0.0.1:5432/postgres"
PG = "$(ls -d /usr/lib/postgresql/*/bin)"
# Guest kernel has no SysV shm (shmget -> ENOSYS): sandbox/shmshim.c fakes the one interlock segment Postgres needs.
PG_BUILD = ("set -e; exec 2>&1; apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql "
            "gcc libc6-dev >/dev/null; gcc -shared -fPIC -O2 -o /usr/local/lib/shmshim.so /dep/shmshim.c && "
            "echo /usr/local/lib/shmshim.so > /etc/ld.so.preload; mkdir -p /pg /run/postgresql && "
            f"chown postgres /pg /run/postgresql && su postgres -c \"timeout 60 {PG}/initdb -D /pg -A trust -U postgres "
            "-E UTF8 --locale=C.UTF-8 -c shared_memory_type=mmap -c dynamic_shared_memory_type=mmap >/dev/null\"; ")
# App #1 (the template) default: uv.lock deps on python:3.14. Other apps set profile["sandbox"] = {image, dep_files, deps}.
TEMPLATE_SANDBOX = {"image": "python:3.14-slim", "dep_files": ["pyproject.toml", "uv.lock", "backend/pyproject.toml"],
                    "deps": ("pip install -q uv && cd /dep && uv export -q --frozen --no-dev --no-hashes --no-emit-project "
                             "--no-emit-workspace --package app -o r.txt && uv pip install -q --system -r r.txt "
                             "pytest==9.1.1")}


def recipe(prof: dict) -> tuple:
    sbx = prof.get("sandbox") or TEMPLATE_SANDBOX
    return sbx["image"], PG_BUILD + sbx["deps"]


def dep_files(repo: Path, ref: str, prof: dict) -> dict:
    sbx = prof.get("sandbox") or TEMPLATE_SANDBOX
    dep = {f"/dep/{p}": git_out(repo, "show", f"{ref}:{p}") for p in sbx["dep_files"]}
    dep["/dep/shmshim.c"] = (HERE / "sandbox" / "shmshim.c").read_bytes()
    return dep
RUN = (f"cd /w && su postgres -c \"timeout 40 {PG}/pg_ctl -D /pg -l /tmp/pg.log -t 30 -w start\" >/dev/null "
       f"&& timeout 400 python {INNER_NAME} --inner; tail -3 /tmp/pg.log >&2")


def git_out(repo: Path, *a) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True).stdout


def tree_files(repo: Path, ref: str, test: bytes, env_file: Path, prof: dict | None = None) -> dict:
    prof = prof or pl.profile()
    tdir = "/w/" + Path(prof["cwd"], prof["tests_dir"], "authz").as_posix().lstrip("./")
    f = {"/w/src.tar": git_out(repo, "archive", "--format=tar", ref, *prof["archive"]),
         f"{tdir}/__init__.py": b"", f"{tdir}/test_regression.py": test, "/w/profile.json": json.dumps(prof).encode(),
         "/w/" + INNER_NAME: (HERE / INNER_NAME).read_bytes(), "/w/regress_run.py": (HERE / "regress_run.py").read_bytes(),
         "/w/probe_lib.py": (HERE / "probe_lib.py").read_bytes()}
    if Path(env_file).exists():
        f["/w/.env"] = Path(env_file).read_bytes()
    return f


def parse_result(stdout: str, ref: str) -> dict:
    line = next((x for x in reversed(stdout.splitlines()) if x.startswith(MARK)), None)
    if line is None:
        return {"ref": ref, "junit": "<testsuite/>", "app_hash_before": "", "app_hash_after": "?",
                "stdout": stdout[-3000:]}
    return json.loads(line[len(MARK):])


def retry(fn, tries: int = 4, sleep=time.sleep):
    """Bounded backoff on transient API failures only (5xx, transport, timeout, 429). 4xx fails fast."""
    from contree_sdk.sdk.exceptions import ApiStatusCodeError, ApiTimeoutError, ContreeTransportError
    for i in range(tries):
        try:
            return fn()
        except (ApiStatusCodeError, ApiTimeoutError, ContreeTransportError) as e:
            status = getattr(e, "status", None)
            if (status is not None and status < 500 and status != 429) or i == tries - 1:
                raise
            print(f"sandbox: transient {type(e).__name__} {status}, retry {i + 1}/{tries - 1}", file=sys.stderr)
            sleep(2 ** (i + 1))


def set_network(client, on: bool) -> None:
    """SDK 0.3.6 has no networking parameter; the API does (networking.enabled, default true). Inject it into
    every POST /instances body. ponytail: private-attr hook, drop when the SDK exposes the flag."""
    api = client._api
    orig = api.__dict__.get("_orig_build") or api._build_request
    api._orig_build = orig
    if on:
        api._build_request = orig
        return

    def build(endpoint_info, data):
        if endpoint_info.method.lower() == "post" and endpoint_info.path.endswith("/instances"):
            body = dict(endpoint_info.get_body_data_by_data(data), networking={"enabled": False})
            return api._client.build_request("POST", endpoint_info.get_path_by_data(data), json=body)
        return orig(endpoint_info=endpoint_info, data=data)
    api._build_request = build


def make_client():
    env = HERE / ".env"  # repo-local, gitignored; only the host process reads it
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"'))
    os.environ.setdefault("NEBIUS_AI_PROJECT", os.environ.get("NEBIUS_PROJECT_ID", ""))
    from contree_sdk import ContreeSync
    return ContreeSync()


def snapshot(client, repo: Path, ref: str = "base", prof: dict | None = None):
    """One image per (app, base SHA) with deps + Postgres, reused by tag across runs and scenarios."""
    from contree_sdk.sdk.exceptions import ContreeError
    prof = prof or pl.profile()
    image, build = recipe(prof)
    sha = git_out(repo, "rev-parse", ref).decode().strip()
    rh = hashlib.sha256((image + build).encode() + (HERE / "sandbox" / "shmshim.c").read_bytes()).hexdigest()
    tag = f"authzlock-{Path(repo).name}-{sha[:12]}-{rh[:8]}"  # new base SHA or new recipe = new snapshot
    try:
        return client.images.use(tag, strict=True)
    except ContreeError:
        pass
    set_network(client, True)  # the build alone needs the network (apt, PyPI)
    dep = dep_files(repo, ref, prof)
    base = base_image(client, image)
    img = retry(lambda: base.run(shell=build, files=dep, disposable=False, timeout=900).wait())
    if img.exit_code != 0:
        raise RuntimeError(f"snapshot build failed: {(img.stderr or img.stdout or '')[-1500:]}")
    return img.tag_as(tag)


def base_image(client, image: str):
    """Use the project's copy of a public image, importing it from Docker Hub the first time (app #2's 3.9)."""
    from contree_sdk.sdk.exceptions import ContreeError
    try:
        return client.images.use(image, strict=True)
    except ContreeError:
        ref = image if "/" in image else f"docker.io/library/{image}"
        return retry(lambda: client.images.pull(ref, new_tag=image, timeout=900))


def run_ref(client, img, repo: Path, ref: str, test: bytes, env_file: Path, prof: dict | None = None) -> dict:
    files = tree_files(repo, ref, test, env_file, prof)
    r = retry(lambda: img.run(shell=RUN, files=files, disposable=True, timeout=600).wait())
    return dict(parse_result(r.stdout or "", ref), ref=ref)


def prove_sandbox(art: Path, s: dict, repo: Path, client=None, env_file: Path | None = None,
                  prof: dict | None = None) -> dict:
    prof = prof or pl.profile()
    env_file = env_file or HERE / prof["env_file"]
    client = client or make_client()
    img = snapshot(client, Path(repo), "base", prof)
    set_network(client, False)
    test = (Path(art) / TEST).read_bytes()
    sides = (("base", "base"), ("head", s["scenario"]))
    with ThreadPoolExecutor(2) as ex:  # base and head are independent VMs: run them concurrently
        res = list(ex.map(lambda sr_: run_ref(client, img, Path(repo), sr_[1], test, env_file, prof), sides))
    return {side: r for (side, _), r in zip(sides, res)}


def inner() -> None:
    """Guest side: unpack the committed tree, migrate, pytest --junitxml, print one result line."""
    import tarfile
    from regress_run import run_env, run_pytest
    with tarfile.open("/w/src.tar") as t:
        t.extractall("/w", filter="data")
    prof = pl.load_profile("/w/profile.json")
    cwd = Path("/w", prof["cwd"])
    env = run_env(prof, GUEST_PG, "postgres", cwd)
    print(MARK + json.dumps(run_pytest(cwd, prof, env, Path("/w/junit.xml"))))


def main(argv: list[str]) -> None:
    from agent.regress import prove_local, spec
    from proof import is_proof
    runner = argv[argv.index("--runner") + 1] if "--runner" in argv else "sandbox"
    repo, diffs, tests, out = (Path(a).resolve() for a in [a for a in argv if not a.startswith("--")
                                                             and a not in ("sandbox", "local")][:4])
    out.mkdir(parents=True, exist_ok=True)
    client = make_client() if runner == "sandbox" else None
    t = time.time()
    if client:
        snapshot(client, repo, "base")
    setup_s = round(time.time() - t, 1)

    def one(tf: Path) -> dict:
        scn = tf.name.removesuffix(".test_regression.py")
        s = spec(json.loads((diffs / f"{scn}.diff.json").read_text()), scn)
        art = Path(tempfile.mkdtemp(prefix="authz_sbx_"))
        (art / "tests/authz").mkdir(parents=True, exist_ok=True)
        (art / TEST).write_bytes(tf.read_bytes())
        t = time.time()
        r = prove_sandbox(art, s, repo, client=client) if client else prove_local(art, s, repo)
        ok, why = is_proof(r["base"]["junit"], r["head"]["junit"], tf.read_text(), finding_path=s["path"],
                           canary=s["canary"], test_path=TEST, written=[TEST],
                           app_hash_before=r["head"]["app_hash_before"], app_hash_after=r["head"]["app_hash_after"])
        (out / f"{scn}.{runner}.json").write_text(json.dumps(r, indent=1))
        row = {"scenario": scn, "runner": runner, "proven": ok, "why": why, "seconds": round(time.time() - t, 1),
               "base_tail": r["base"]["stdout"][-300:], "head_tail": r["head"]["stdout"][-600:]}
        print(json.dumps({k: row[k] for k in ("scenario", "runner", "proven", "why", "seconds")}), flush=True)
        return row
    t = time.time()
    # Sandboxes: every scenario at once (2 VMs each, beta cap is 50 concurrent ops). Local shares one Postgres: serial.
    with ThreadPoolExecutor(8 if client else 1) as ex:
        rows = list(ex.map(one, sorted(tests.glob("pr-*.test_regression.py"))))
    wall = round(time.time() - t, 1)
    summary = {"runner": runner, "setup_seconds": setup_s, "proofs_wall_seconds": wall, "proven": sum(r["proven"] for r in rows),
               "total": len(rows), "scenarios": rows}
    (out / f"summary.{runner}.json").write_text(json.dumps(summary, indent=1))
    print(f"{runner}: {summary['proven']}/{summary['total']} proven, setup {setup_s}s, proofs wall {wall}s")


if __name__ == "__main__":
    inner() if sys.argv[1:] == ["--inner"] else main(sys.argv[1:])
