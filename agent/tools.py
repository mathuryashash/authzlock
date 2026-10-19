"""Agent tools. Untrusted model output arrives here, so: writes are jailed to .authzlock/artifacts/,
reads to the repo, commands are fixed templates, unknown tools/bad args return errors, every call is logged."""
import json
import subprocess
import sys
from pathlib import Path

ARTIFACTS = Path(".authzlock") / "artifacts"
ENGINE = Path(__file__).resolve().parent.parent / "authzlock.py"
# Fixed command templates only: no free shell (security #5). Run inside the no-secrets sandbox/container.
TEMPLATES = {
    "pytest_artifacts": [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                         "--junitxml", str(ARTIFACTS / "junit.xml"), str(ARTIFACTS)],
    # Base lock from the agent's artifacts only. The worker it spawns gets the env allowlist (no API keys).
    "lock_artifacts": [sys.executable, str(ENGINE), "lock", "--checkout", ".", "--tag", "agent_check",
                       "--out", str(Path(".authzlock") / "agent_check.lock.json"),
                       "--manifest", str(ARTIFACTS / "manifest.json"), "--seeder", str(ARTIFACTS / "seeder.py")],
}

SCHEMAS = [
    {"type": "function", "function": {"name": "read_file", "description": "Read a repo file (truncated).",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "write_file",
     "description": "Write an artifact under .authzlock/artifacts/ (path is relative to it).",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                    "required": ["path", "content"]}}},
    {"type": "function", "function": {"name": "run", "description": "Run a fixed command template.",
     "parameters": {"type": "object", "properties": {"template": {"type": "string", "enum": sorted(TEMPLATES)}},
                    "required": ["template"]}}},
]


def jail(root: Path, rel: str) -> Path:
    if not rel or Path(rel).is_absolute() or Path(rel).drive:
        raise ValueError(f"path must be relative: {rel!r}")
    root = root.resolve()
    p = (root / rel).resolve()
    if not p.is_relative_to(root) or p == root:
        raise ValueError(f"path escapes {root.name}/: {rel!r}")
    return p


def run_env() -> dict:
    import os
    return {k: v for k, v in os.environ.items() if not any(x in k.upper() for x in ("KEY", "TOKEN", "SECRET"))}


def _run(argv, cwd):
    # ponytail: runs on the local host for now; D3 moves this into the no-secrets, --network none container.
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=600,
                       env=run_env())
    return f"exit={p.returncode}\n{(p.stdout + p.stderr)[-4000:]}"


class Tools:
    def __init__(self, repo: Path, max_read: int = 20_000, runner=_run):
        self.repo, self.max_read, self.runner = Path(repo), max_read, runner
        self.art = self.repo / ARTIFACTS
        self.log = self.repo / ".authzlock" / "tool_calls.jsonl"

    def read_file(self, path: str) -> str:
        p = jail(self.repo, path)
        if p.name == ".env" or p.suffix == ".env":
            raise ValueError("env files hold secrets and are not readable")
        text = p.read_text(errors="replace")
        return text if len(text) <= self.max_read else text[:self.max_read] + "\n...[truncated]"

    def write_file(self, path: str, content: str) -> str:
        p = jail(self.art, path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return f"ok: wrote {len(content)} chars to {p.relative_to(self.repo).as_posix()}"

    def run(self, template: str) -> str:
        if template not in TEMPLATES:
            raise ValueError(f"unknown template {template!r}; allowed: {sorted(TEMPLATES)}")
        return self.runner(list(TEMPLATES[template]), self.repo)

    def dispatch(self, name: str, arguments: str) -> str:
        try:
            if name not in ("read_file", "write_file", "run"):
                raise ValueError(f"unknown tool {name!r}")
            args = json.loads(arguments or "{}")
            out = getattr(self, name)(**args)
        except Exception as e:  # the model gets the error back and can repair; the loop never crashes
            out = f"error: {type(e).__name__}: {e}"
        self.log.parent.mkdir(parents=True, exist_ok=True)
        with self.log.open("a") as f:
            f.write(json.dumps({"tool": name, "args": arguments[:500], "result": out[:300]}) + "\n")
        return out
