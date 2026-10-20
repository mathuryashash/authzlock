"""Keyless replay: recompute every verdict and proof from committed artifacts and render the HTML reports.

  python replay.py [site_dir]      # default site_dir = docs/  (GitHub Pages)
No API key, no Postgres, no target app needed: it reads the committed lockfiles (probe results) and JUnit XML
(proof results), re-runs the deterministic verdict (authzlock.diff) and proof check (proof.is_proof), and exits 1
if any verdict differs from the expected one in results/cases.json.
"""
import json
import sys
from pathlib import Path

import report
from authzlock import diff
from proof import is_proof

ROOT = Path(__file__).resolve().parent
TEST = "tests/authz/test_regression.py"


def load(p) -> dict:
    return json.loads((ROOT / p).read_text(encoding="utf-8"))


def check_proof(pr: dict) -> tuple[bool, list]:
    ev = pr["evidence"]
    return is_proof(ev["base"]["junit"], ev["head"]["junit"], pr["test"], finding_path=pr["path"],
                    canary=pr["canary"], test_path=TEST, written=[TEST],
                    app_hash_before=ev["head"]["app_hash_before"], app_hash_after=ev["head"]["app_hash_after"])


def main(site: Path) -> int:
    cases = load("results/cases.json")
    site.mkdir(parents=True, exist_ok=True)
    rows, bad = [], 0
    for app, c in cases["apps"].items():
        base = load(c["base"])
        report_name = f"{app}-base.html"
        (site / report_name).write_text(report.render(base, f"{c['name']}: base lock", meta={"app": c["name"]}),
                                        encoding="utf-8")
        for s in c["scenarios"]:
            sbase = load(s["base"]) if s.get("base") else base  # benchmark runs carry their own base lock
            d = diff(sbase, load(s["head"]))
            proof = s.get("proof") and load(s["proof"])
            pok = check_proof(proof)[0] if proof else None
            # reproduce = same verdict as the recorded run (a benchmark miss is recorded honestly, not hidden)
            ok = d["verdict"] == s.get("recorded", s["expected"]) and pok is not False
            bad += not ok
            name = f"{app}-{s['id']}.html"
            meta = {"app": c["name"], "expected": s["expected"], "what": s["desc"]}
            if s.get("proof_status"):  # agent never produced a proof that holds: said so, not hidden
                meta["regression test"] = s["proof_status"]
            if proof:
                meta["regression test"] = "proven (JUnit: passes on base, AssertionError on head)" if pok else "NOT proven"
                meta["proof LLM cost"] = proof.get("cost", "")
            (site / name).write_text(report.render(load(s["head"]), f"{c['name']}: {s['id']}", sbase, meta),
                                     encoding="utf-8")
            rows.append((app, s["id"], s["expected"], d["verdict"], pok, ok, name, s.get("kind", "scenario")))
            miss = "" if d["verdict"] == s["expected"] else "  <- benchmark MISS (expected differs)"
            print(f"{'ok ' if ok else 'BAD'} {app:5} {s['id']:34} expected {s['expected']:4} got {d['verdict']:7}"
                  + ("" if pok is None else f" proof={'proven' if pok else 'NOT proven'}") + miss)
    idx = ["<!doctype html><html><head><meta charset=utf-8>",
           "<meta http-equiv=Content-Security-Policy content=\"default-src 'none'; style-src 'unsafe-inline'\">",
           f"<title>authz.lock reports</title><style>{report.CSS}</style></head><body><h1>authz.lock reports</h1>",
           "<p>Rendered by <code>python replay.py</code> from committed lockfiles; verdicts recomputed keylessly "
           "(no LLM, no API key). Source: github.com/mathuryashash/authzlock</p><ul>"]
    idx += [f'<li><a href="{a}-base.html">{report.e(c["name"])}: base lock</a></li>' for a, c in cases["apps"].items()]
    idx += ["</ul><table><tr><th>app</th><th>PR</th><th>kind</th><th>expected</th><th>verdict</th><th>proof</th></tr>"]
    idx += [f'<tr class="{"P" if ok else "F"}"><td>{a}</td><td><a href="{n}">{report.e(i)}</a></td><td>{k}</td>'
            f'<td>{e_}</td><td class="{"P" if v == e_ else "F"}">{v}{"" if v == e_ else " (miss)"}</td><td>{"-" if p is None else "proven" if p else "NOT proven"}</td></tr>'
            for a, i, e_, v, p, ok, n, k in rows]
    hit = sum(v == e_ for _, _, e_, v, *_ in rows)
    idx.append(f"</table><p>{len(rows) - bad}/{len(rows)} verdicts reproduced from the recorded runs; "
               f"{hit}/{len(rows)} equal the expected verdict.</p></body></html>")
    (site / "index.html").write_text("\n".join(idx), encoding="utf-8")
    print(f"{len(rows) - bad}/{len(rows)} verdicts reproduced; {sum(r[2] == r[3] for r in rows)}/{len(rows)} "
          f"equal expected; reports in {site}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs"))
