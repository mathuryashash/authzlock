"""Proof criteria for agent-written regression tests (security #4). Deterministic; parses JUnit XML."""
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath


def _cases(junit: str) -> list:
    root = ET.fromstring(junit)
    return list(root.iter("testcase"))


def is_proof(base_junit: str, head_junit: str, test_src: str, *, finding_path: str, canary: str, test_path: str,
             written: list[str], app_hash_before: str, app_hash_after: str) -> tuple[bool, list[str]]:
    why = []
    base, head = _cases(base_junit), _cases(head_junit)
    if not base or any(c.find("failure") is not None or c.find("error") is not None or c.find("skipped") is not None
                       for c in base):
        why.append("base: every test must run and pass")
    fails = [c.find("failure") for c in head]
    if not head or not any(f is not None and "AssertionError" in (f.get("message", "") + (f.text or ""))
                           and test_path in (f.text or "") for f in fails):
        why.append("head: no AssertionError raised inside the test file")
    if any(c.find("error") is not None for c in head):
        why.append("head: errors (import/fixture) are not proofs")
    literal = finding_path.split("{")[0].rstrip("/")
    if literal not in test_src or canary not in test_src:
        why.append(f"test must reference path {finding_path!r} and canary {canary!r}")
    bad = [w for w in written if PurePosixPath(w).parts[:2] != ("tests", "authz")]
    if bad:
        why.append(f"writes outside tests/authz/: {bad}")
    if app_hash_before != app_hash_after:
        why.append("app source changed")
    return not why, why
