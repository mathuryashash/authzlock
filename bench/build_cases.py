"""One-time: copy the evidence replay needs into results/ and write results/cases.json (keyless replay inputs).

  python -m bench.build_cases
Inputs are the runs recorded in results/ (+ .authzlock/agent_scen for app #1 head locks, bench/results for the
mutation benchmark). Proof evidence = JUnit XML from the Sandboxes proof runs of the agent-written tests.
"""
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
from bench.make_mutations import HELDOUT, MUTATIONS  # noqa: E402  (ROOT on sys.path when run as a module)

A1 = [("pr-benign-pagination", "PASS", "Benign: default page size 100 -> 50"),
      ("pr-benign-stats", "PASS", "Benign: new owner-scoped GET /items/stats"),
      ("pr-idor-refactor", "FAIL", "Refactor drops the ownership check on GET /items/{id}"),
      ("pr-export-csv", "FAIL", "AI-written GET /items/export CSV with no owner filter"),
      ("pr-mass-assign", "FAIL", "is_superuser added to the /users/me update schema"),
      ("pr-count-leak", "FAIL", "'Simplified' count query leaks the total item count")]
A2 = [("pr-todo-get-by-id", "FAIL", "New GET /todos/{todo_id} with no created_by_id filter"),
      ("pr-category-cleanup", "FAIL", "Non-owners may delete shared default categories"),
      ("pr-todos-completed-filter", "PASS", "Benign: ?completed= filter on GET /todos")]


def proof(sbx: Path, test: Path, diff: dict, scn: str, cost: str) -> dict:
    from agent.regress import spec
    s = spec(diff, scn)
    ev = json.loads(sbx.read_text(encoding="utf-8"))
    return {"scenario": scn, "path": s["path"], "canary": s["canary"], "test": test.read_text(encoding="utf-8"),
            "cost": cost, "evidence": {k: {f: ev[k][f] for f in ("junit", "app_hash_before", "app_hash_after")}
                                       for k in ("base", "head")}}


def main() -> None:
    out = {"apps": {}}
    dst = ROOT / "results/app1/scenarios"
    dst.mkdir(parents=True, exist_ok=True)
    scen = []
    for scn, exp, desc in A1:
        shutil.copy(ROOT / ".authzlock/agent_scen" / f"{scn.replace('-', '_')}.lock.json", dst / f"{scn}.lock.json")
        c = {"id": scn, "expected": exp, "desc": desc, "head": f"results/app1/scenarios/{scn}.lock.json"}
        sbx = ROOT / "results/sandbox_run1" / f"{scn}.sandbox.json"
        if sbx.exists():
            d = json.loads((ROOT / ".authzlock/agent_scen" / f"{scn}.diff.json").read_text(encoding="utf-8"))
            p = proof(sbx, ROOT / "results/agent_regress2" / f"{scn}.test_regression.py", d, scn,
                      "$0.089 for all 4 app #1 FAIL PRs (Super test agent + Ultra root cause), results/agent_regress2")
            (dst / f"{scn}.proof.json").write_text(json.dumps(p, indent=1))
            c["proof"] = f"results/app1/scenarios/{scn}.proof.json"
        scen.append(c)
    shutil.copy(ROOT / ".authzlock/agent_scen/base_run2.lock.json", dst / "same-sha.lock.json")
    scen.insert(0, {"id": "same-sha", "expected": "PASS", "desc": "Same SHA, second run (fresh seed + canaries)",
                    "head": "results/app1/scenarios/same-sha.lock.json"})
    out["apps"]["app1"] = {"name": "full-stack-fastapi-template@cb740b6", "base": "results/app1/base.lock.json",
                           "scenarios": scen}
    scen = [{"id": "same-sha", "expected": "PASS", "desc": "Same SHA, second run",
             "head": "results/app2/scenarios/base_run2.lock.json"}]
    for scn, exp, desc in A2:
        c = {"id": scn, "expected": exp, "desc": desc, "head": f"results/app2/scenarios/{scn.replace('-', '_')}.lock.json"}
        sbx = ROOT / "results/app2/sandbox_proofs" / f"{scn}.sandbox.json"
        if sbx.exists():
            d = json.loads((ROOT / "results/app2/scenarios" / f"{scn}.diff.json").read_text(encoding="utf-8"))
            run = "regress_sandbox_run3" if scn == "pr-todo-get-by-id" else "regress_sandbox_run2"
            p = proof(sbx, ROOT / "results/app2" / run / f"{scn}.test_regression.py", d, scn,
                      {"pr-todo-get-by-id": "$0.022 (results/app2/regress_sandbox_run3)",
                       "pr-category-cleanup": "part of $0.083 (results/app2/regress_sandbox_run2)"}[scn])
            dp = ROOT / "results/app2/scenarios" / f"{scn}.proof.json"
            dp.write_text(json.dumps(p, indent=1))
            c["proof"] = dp.relative_to(ROOT).as_posix()
        scen.append(c)
    out["apps"]["app2"] = {"name": "fastapi-todos@c059889", "base": "results/app2/scenarios/base_run1.lock.json",
                           "scenarios": scen}
    # Mutation benchmark. v0 = probe before the foreign-reference variant (original 11+3 in bench/results, the
    # held-out 4+1 in bench/results_preheldout, both vs the recorded base lock); v1 = with it (bench/results_v1,
    # vs a base lock rebuilt by the same probe version).
    runs = [("v0", "bench/results", None), ("v0", "bench/results_preheldout", None),
            ("v1", "bench/results_v1", "bench/results_v1/{app}/base.lock.json")]
    for app in ("app1", "app2"):
        scen = out["apps"][app]["scenarios"]
        for ver, rdir, rbase in runs:
            rbase = rbase and rbase.format(app=app)
            if rbase:  # the rebuilt base itself, diffed against the recorded one: no probed cell may change
                scen.append({"id": f"base.{ver}", "expected": "PASS", "kind": f"probe {ver} base", "head": rbase,
                             "desc": f"Base lock rebuilt by probe {ver} vs the recorded base (new cells only add)"})
            for name, exp, desc, _ in MUTATIONS[app]:
                lk = ROOT / rdir / app / f"{name}.lock.json"
                if not lk.exists():
                    continue
                rec = json.loads(lk.with_name(f"{name}.diff.json").read_text(encoding="utf-8"))["verdict"]
                c = {"id": f"{name}.{ver}", "expected": exp, "recorded": rec, "desc": desc,
                     "kind": f"mutation {ver}" + (" held-out" if name in HELDOUT else ""),
                     "head": lk.relative_to(ROOT).as_posix(), **({"base": rbase} if rbase else {})}
                pj = lk.with_name(f"{name}.proof.json")
                tries = [x for rs in sorted((ROOT / rdir / app).glob("regress*/regress_summary.json"))
                         for x in json.loads(rs.read_text(encoding="utf-8"))["scenarios"]
                         if x["scenario"] == name and x.get("evidence")]  # every recorded run, proven first
                r = next((x for x in tries if x["status"] == "proven"), None)
                if tries and not r:
                    c["proof_status"] = f"unproven after {len(tries)} agent run(s)"
                if r:
                    pj.write_text(json.dumps({"scenario": name, "path": r["finding"]["path"],
                                              "canary": r["finding"]["canary"], "test": r["test"],
                                              "cost": f"${r['usd']} ({r['calls']} calls, {r['prove_runs']} prove runs in "
                                                      f"Nebius Sandboxes, {r['seconds']} s)",
                                              "evidence": r["evidence"]}, indent=1))
                if pj.exists():
                    c["proof"] = pj.relative_to(ROOT).as_posix()
                scen.append(c)
    (ROOT / "results/cases.json").write_text(json.dumps(out, indent=1))
    print(sum(len(a["scenarios"]) for a in out["apps"].values()), "cases")

if __name__ == "__main__":
    main()
