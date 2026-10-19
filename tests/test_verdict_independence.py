"""The design claim: no LLM decides the verdict. Enforced structurally and behaviourally."""
import ast
import json
import re
import subprocess
from pathlib import Path

import authzlock

ROOT = Path(__file__).resolve().parent.parent
VERDICT_FILES = ["authzlock.py", "probe_worker.py", "proof.py", "compare.py"]
FORBIDDEN = {"agent", "openai", "tavily"}


def imported_modules(path: Path) -> set:
    mods = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            mods |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    return mods


def test_verdict_code_never_imports_llm_client():
    for f in VERDICT_FILES:
        assert not imported_modules(ROOT / f) & FORBIDDEN, f


def test_verdict_independent_of_llm():
    """Same lock inputs -> same verdict, whether or not the agent ran (diff() is pure)."""
    base = json.loads((ROOT / "results" / "base_run1.lock.json").read_text())
    base["harness"] = {"valid": True, "failures": []}  # pre-gate fixture; missing gates => NEUTRAL
    head = json.loads(json.dumps(base))
    cell = next(k for k, v in head["cells"].items() if v["decision"] == "DENY")
    head["cells"][cell] = dict(head["cells"][cell], decision="ALLOW", status=200, leaks=["owner_b"])
    first = authzlock.diff(base, head)
    assert first["verdict"] == "FAIL"
    assert authzlock.diff(base, head) == first
    assert authzlock.diff(base, json.loads(json.dumps(base)))["verdict"] == "PASS"


def test_no_secrets_in_repo():
    files = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True,
                           check=True).stdout.split()
    pat = re.compile(r"NEBIUS_API_KEY\s*=\s*['\"]?[A-Za-z0-9_\-]{12,}|tvly-[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}"
                     r"|ghp_[A-Za-z0-9]{30,}")
    hits = [f for f in files if (ROOT / f).is_file() and pat.search((ROOT / f).read_text(errors="ignore"))]
    assert hits == []
