"""Security #3: a lazy LLM seeder must never make the invariants pass vacuously -> 'harness invalid' (NEUTRAL)."""
import json
from pathlib import Path

import authzlock

ROOT = Path(__file__).resolve().parent.parent
MAN = json.loads((ROOT / "manifest.json").read_text())


def res(op, ident, status=200, leaks=(), target="-"):
    return {"op": op, "identity": ident, "target": target, "variant": "base", "status": status,
            "leaks": list(leaks), "smtp_leaks": [], "db": [], "count": None, "error": None}


def raw(roles, results):
    return {"tag": "t", "probes": len(results), "elapsed_s": 0, "roles": roles, "results": results}


GOOD_ROLES = {"user_a": {"owns_items": 2, "canaried_rows": 2}, "user_b": {"owns_items": 1, "canaried_rows": 1},
              "superuser": {"owns_items": 1, "canaried_rows": 1}}
GOOD_RESULTS = [res("GET /items/", "user_a", leaks=["user_a"]), res("GET /items/", "user_b", leaks=["user_b"])]


def test_good_harness_is_valid():
    lock = authzlock.build_lock(raw(GOOD_ROLES, GOOD_RESULTS), MAN)
    assert lock["harness"] == {"valid": True, "failures": []}


def test_one_owner_seeder_is_harness_invalid():
    roles = dict(GOOD_ROLES, user_b={"owns_items": 0, "canaried_rows": 0})
    lock = authzlock.build_lock(raw(roles, GOOD_RESULTS), MAN)
    assert not lock["harness"]["valid"]
    assert any("2 non-privileged owners" in f for f in lock["harness"]["failures"])


def test_rows_without_canary_do_not_count():
    roles = dict(GOOD_ROLES, user_a={"owns_items": 3, "canaried_rows": 0})
    assert not authzlock.build_lock(raw(roles, GOOD_RESULTS), MAN)["harness"]["valid"]


def test_owner_that_cannot_read_own_canary_is_harness_invalid():
    results = [res("GET /items/", "user_a", leaks=["user_a"]), res("GET /items/", "user_b", status=403)]
    lock = authzlock.build_lock(raw(GOOD_ROLES, results), MAN)
    assert not lock["harness"]["valid"]
    assert any("user_b" in f and "self-read" in f for f in lock["harness"]["failures"])


def test_invalid_harness_is_neutral_never_pass_or_fail():
    good = authzlock.build_lock(raw(GOOD_ROLES, GOOD_RESULTS), MAN)
    bad_roles = dict(GOOD_ROLES, user_b={"owns_items": 0, "canaried_rows": 0})
    bad = authzlock.build_lock(raw(bad_roles, GOOD_RESULTS), MAN)
    assert authzlock.diff(good, good)["verdict"] == "PASS"
    for b, h in ((good, bad), (bad, good), (bad, bad)):
        d = authzlock.diff(b, h)
        assert d["verdict"] == "NEUTRAL" and d["harness_invalid"]
