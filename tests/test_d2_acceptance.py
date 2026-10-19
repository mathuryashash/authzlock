"""Plan test #8 (integration): agent-written artifacts reproduce the hand-written harness on the 8 scenarios.
Needs Postgres + the pinned template; run:  python run_scenarios.py target .authzlock/ref/scen manifest.json
seeders/fullstack_template.py  and the same with .authzlock/agent_scen + agent artifacts. Skips otherwise."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REF, AGENT = ROOT / ".authzlock/ref/scen", ROOT / ".authzlock/agent_scen"


@pytest.mark.skipif(not ((REF / "summary.json").exists() and (AGENT / "summary.json").exists()),
                    reason="scenario runs not present (needs Postgres + target)")
def test_generated_seeder_reproduces_8_scenario_verdicts():
    out = json.loads(subprocess.run([sys.executable, str(ROOT / "compare.py"), str(REF), str(AGENT)],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["same_verdicts"] == 8 and all(v[1].split()[0] == v[3] for v in out["verdicts"])
    assert out["harness_b"]["valid"] and out["base"]["coverage"][1] >= 20
    assert out["base"]["cell_mismatches"] == [] and out["base"]["violation_diff"] == []
