"""Run the evaluation scenarios: determinism, 2 benign PRs, 4 authz-regression PRs, dev-vs-prod profile.

Base lock is computed once per base SHA and reused (cache), as the design specifies.
"""
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from authzlock import cmd_lock, diff, render_report

HERE = Path(__file__).resolve().parent
REPO = Path(sys.argv[1] if len(sys.argv) > 1 else "/home/claude/tpl").resolve()
OUT = HERE / "results"
OUT.mkdir(exist_ok=True)
PROD_ENV, DEV_ENV = HERE / "target.env", HERE / "dev.env"

SCENARIOS = [
    # (branch, expected, what it is)
    ("pr-benign-pagination", "PASS", "Benign: default page size 100 -> 50"),
    ("pr-benign-stats", "PASS", "Benign: new owner-scoped /items/stats endpoint"),
    ("pr-idor-refactor", "FAIL", "Refactor moves item lookup to a helper and silently drops the ownership check on GET /items/{id}"),
    ("pr-export-csv", "FAIL", "AI-written CSV export endpoint that forgets the owner filter"),
    ("pr-mass-assign", "FAIL", "is_superuser / is_active added to the /users/me update schema"),
    ("pr-count-leak", "FAIL", "'Simplified' count query leaks the total item count to normal users"),
]


def checkout(ref: str, env_file: Path) -> Path:
    tree = OUT / f"wt_{ref}"
    if tree.exists():
        subprocess.run(["git", "-C", str(REPO), "worktree", "remove", "--force", str(tree)], capture_output=True)
    subprocess.run(["git", "-C", str(REPO), "worktree", "add", "--detach", str(tree), ref], check=True,
                   capture_output=True)
    shutil.copy(env_file, tree / ".env")
    (tree / ".venv").symlink_to(REPO / ".venv")
    return tree


def cleanup(tree: Path):
    subprocess.run(["git", "-C", str(REPO), "worktree", "remove", "--force", str(tree)], capture_output=True)


def lock_for(ref: str, tag: str, env_file: Path) -> dict:
    tree = checkout(ref, env_file)
    try:
        return cmd_lock(tree, OUT / f"{tag}.lock.json", tag)
    finally:
        cleanup(tree)


summary = []
t = time.time()
base = lock_for("base", "base_run1", PROD_ENV)
print(f"base lock: {base['probes']} probes, {base['elapsed_s']}s, violations={len(base['violations'])}, "
      f"coverage={base['coverage']['probed']}/{base['coverage']['operations']}", flush=True)

# 1. determinism: same SHA, fresh seed + fresh random canaries
again = lock_for("base", "base_run2", PROD_ENV)
d = diff(base, again)
(OUT / "same-sha.report.md").write_text(render_report("base vs base (same SHA, second run)", base, again, d))
summary.append({"scenario": "same SHA twice", "expected": "PASS", "verdict": d["verdict"],
                "changed_cells": len(d["changes"]), "new_violations": len(d["new_violations"])})
print(summary[-1], flush=True)

# 2. PR scenarios
for ref, expected, desc in SCENARIOS:
    head = lock_for(ref, ref.replace("-", "_"), PROD_ENV)
    d = diff(base, head)
    (OUT / f"{ref}.report.md").write_text(render_report(f"{ref} — {desc}", base, head, d))
    (OUT / f"{ref}.diff.json").write_text(json.dumps(d, indent=1))
    summary.append({"scenario": ref, "description": desc, "expected": expected, "verdict": d["verdict"],
                    "changed_cells": len(d["changes"]),
                    "widened_cells": sum(c["class"] == "WIDENED" for c in d["changes"]),
                    "new_violations": len(d["new_violations"]),
                    "rules": sorted({v["rule"] for v in d["new_violations"]}),
                    "new_ops": d["new_ops"], "head_seconds": head["elapsed_s"]})
    print(summary[-1], flush=True)

# 3. environment profile: identical code, template's shipped dev .env vs production profile
dev = lock_for("base", "base_devprofile", DEV_ENV)
d = diff(base, dev)
(OUT / "dev-profile.report.md").write_text(render_report("same code, development profile vs production profile", base, dev, d))
summary.append({"scenario": "dev profile vs prod profile", "expected": "FAIL (informational)", "verdict": d["verdict"],
                "new_ops": d["new_ops"], "new_violations": len(d["new_violations"]),
                "rules": sorted({v["rule"] for v in d["new_violations"]})})
print(summary[-1], flush=True)

(OUT / "summary.json").write_text(json.dumps({"total_seconds": round(time.time() - t, 1),
                                              "base_coverage": base["coverage"],
                                              "base_violations": base["violations"],
                                              "scenarios": summary}, indent=1))
print("done in", round(time.time() - t, 1), "s")
