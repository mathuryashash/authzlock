"""D2 acceptance: compare decision matrix + invariants of two locks, never the raw lock (canaries are random)."""
from compare import compare_locks


def lock(cells, violations=(), probed=20):
    return {"cells": {k: {"decision": d} for k, d in cells.items()}, "coverage": {"probed": probed, "operations": 22},
            "violations": [{"rule": r, "cell": c} for r, c in violations], "harness": {"valid": True}}


def test_identical_matrices_match():
    a = lock({"GET /x | u | - | base": "ALLOW"})
    assert compare_locks(a, a) == {"same_cells": 1, "cell_mismatches": [], "only_in_a": [], "only_in_b": [],
                                   "violation_diff": [], "coverage": (20, 20)}


def test_mismatches_are_reported():
    a = lock({"GET /x | u | - | base": "ALLOW", "GET /y | u | - | base": "DENY"}, [("I1", "c")])
    b = lock({"GET /x | u | - | base": "DENY", "GET /z | u | - | base": "DENY"}, probed=19)
    r = compare_locks(a, b)
    assert r["cell_mismatches"] == ["GET /x | u | - | base: ALLOW != DENY"]
    assert r["only_in_a"] == ["GET /y | u | - | base"] and r["only_in_b"] == ["GET /z | u | - | base"]
    assert r["violation_diff"] == ["only in a: I1 @ c"] and r["coverage"] == (20, 19)
