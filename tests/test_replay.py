import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_replay_reproduces_all_verdicts_without_keys(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("NEBIUS", "TAVILY", "AUTHZ_PG", "GITHUB_TOKEN"))}
    p = subprocess.run([sys.executable, str(ROOT / "replay.py"), str(tmp_path)], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=300)
    assert p.returncode == 0, p.stdout[-2000:] + p.stderr[-2000:]
    assert "BAD" not in p.stdout and "proof=NOT proven" not in p.stdout
    assert (tmp_path / "index.html").exists() and (tmp_path / "app2-base.html").exists()
    assert "verdicts reproduced" in p.stdout


def test_replay_imports_no_agent_code():
    src = (ROOT / "replay.py").read_text(encoding="utf-8") + (ROOT / "report.py").read_text(encoding="utf-8")
    assert "from agent" not in src and "import agent" not in src and "openai" not in src
