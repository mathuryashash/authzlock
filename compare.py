"""D2 acceptance: do the agent's artifacts reproduce the hand-written harness?
Compares decision matrices, invariant violations, coverage and per-scenario verdicts. Never raw locks.

  python compare.py <ref scenario dir> <agent scenario dir>
"""
import json
import sys
from pathlib import Path


def compare_locks(a: dict, b: dict) -> dict:
    da = {k: v["decision"] for k, v in a["cells"].items()}
    db = {k: v["decision"] for k, v in b["cells"].items()}
    va = {f'{v["rule"]} @ {v["cell"]}' for v in a["violations"]}
    vb = {f'{v["rule"]} @ {v["cell"]}' for v in b["violations"]}
    both = sorted(set(da) & set(db))
    return {"same_cells": sum(da[k] == db[k] for k in both),
            "cell_mismatches": [f"{k}: {da[k]} != {db[k]}" for k in both if da[k] != db[k]],
            "only_in_a": sorted(set(da) - set(db)), "only_in_b": sorted(set(db) - set(da)),
            "violation_diff": [f"only in a: {v}" for v in sorted(va - vb)] + [f"only in b: {v}" for v in sorted(vb - va)],
            "coverage": (a["coverage"]["probed"], b["coverage"]["probed"])}


if __name__ == "__main__":
    ra, rb = Path(sys.argv[1]), Path(sys.argv[2])
    out = {"base": compare_locks(*(json.loads((d / "base_run1.lock.json").read_text()) for d in (ra, rb))),
           "harness_b": json.loads((rb / "base_run1.lock.json").read_text())["harness"]}
    sa, sb = (json.loads((d / "summary.json").read_text())["scenarios"] for d in (ra, rb))
    out["verdicts"] = [(x["scenario"], x["expected"], x["verdict"], y["verdict"]) for x, y in zip(sa, sb)]
    out["same_verdicts"] = sum(x[2] == x[3] for x in out["verdicts"])
    out["base"]["cell_mismatches"] = out["base"]["cell_mismatches"][:20]
    print(json.dumps(out, indent=1))
