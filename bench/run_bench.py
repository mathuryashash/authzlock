"""Mutation benchmark: deterministic probe of every bench/mutations/<app>/*.patch against the cached base lock.

  AUTHZ_PG=... python bench/run_bench.py app1|app2 [name ...]
Writes bench/results/<app>/<name>.diff.json + <name>.lock.json and appends to bench/results/<app>/rows.jsonl.
App setup per app: checkout (target/, target2/), agent artifacts, cached base lock (built with the same artifacts).
"""
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from bench.make_mutations import MUTATIONS  # noqa: E402

APPS = {
    "app1": {"repo": ROOT / "target", "profile": None, "art": ROOT / "results/agent_run1",
             "base": ROOT / "results/app1/base.lock.json"},
    "app2": {"repo": ROOT / "target2", "profile": ROOT / "apps/todos/profile.json",
             "art": ROOT / "results/app2/onboard_run5", "base": ROOT / "results/app2/scenarios/base_run1.lock.json"},
}


def run(app: str, names: list[str]) -> None:
    cfg = APPS[app]
    if cfg["profile"]:
        os.environ["AUTHZ_PROFILE"] = str(cfg["profile"])
    import probe_lib
    from authzlock import cmd_lock, diff
    prof = probe_lib.profile()
    repo, out = cfg["repo"], ROOT / "bench/results" / app
    out.mkdir(parents=True, exist_ok=True)
    os.environ["AUTHZ_PY"] = str(repo / ".venv/Scripts/python.exe") if (repo / ".venv/Scripts").exists() \
        else str(repo / ".venv/bin/python")
    base = json.loads(cfg["base"].read_text(encoding="utf-8"))
    muts = [m for m in MUTATIONS[app] if not names or m[0] in names]

    def one(i_m):
        i, (name, expected, desc, _) = i_m
        tree = ROOT / ".authzlock" / f"bench_wt_{name}"
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(tree)], capture_output=True)
        subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(tree), name], check=True,
                       capture_output=True)
        shutil.copy(ROOT / prof["env_file"], tree / ".env")
        t = time.time()
        try:
            head = cmd_lock(tree, out / f"{name}.lock.json", name.replace("-", "_"), smtp_port=1100 + i,
                            manifest=cfg["art"] / "manifest.json", seeder=cfg["art"] / "seeder.py")
        finally:
            subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(tree)], capture_output=True)
        d = diff(base, head)
        (out / f"{name}.diff.json").write_text(json.dumps(d, indent=1))
        (out / f"{name}.lock.raw.json").unlink(missing_ok=True)
        row = {"app": app, "scenario": name, "expected": expected, "description": desc, "verdict": d["verdict"],
               "rules": sorted({v["rule"] for v in d["new_violations"]}), "new_violations": len(d["new_violations"]),
               "widened_cells": sum(c["class"] == "WIDENED" for c in d["changes"]), "changed_cells": len(d["changes"]),
               "new_ops": d["new_ops"], "probes": head["probes"], "probe_s": head["elapsed_s"],
               "wall_s": round(time.time() - t, 1)}
        with open(out / "rows.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)

    with ThreadPoolExecutor(int(os.environ.get("BENCH_PAR", "2"))) as ex:
        list(ex.map(one, enumerate(muts)))


if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2:])
