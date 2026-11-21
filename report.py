"""Static HTML report: lock JSON (+ optional base lock / diff) -> one self-contained HTML page, no JS.

  python report.py <lock.json> <out.html> [--base base.lock.json] [--title T] [--meta key=value ...]
With --base the page is a PR report: verdict, diff, and the identity x operation grid marks NEW violations/widened
cells. Every string comes from a lock that PR code influenced: html.escape'd, JWTs/passwords redacted (comment.redact),
CSP default-src 'none'.
"""
import argparse
import html
import json
from collections import defaultdict
from pathlib import Path

from authzlock import diff
from comment import redact

CSS = """:root{--bg:#f8f9fb;--surface:#fff;--surface2:#f2f4f7;--line:#dee2e8;--ink:#111827;
--ink2:#4b5565;--muted:#6b7386;--pass:#15803d;--pass-bg:#dcfce7;--fail:#b91c1c;
--fail-bg:#fee2e2;--warn:#92400e;--warn-bg:#fef3c7;--mono:ui-monospace,'Cascadia Mono',Consolas,monospace}
*{box-sizing:border-box}
body{font:14px/1.6 system-ui,-apple-system,'Segoe UI',sans-serif;margin:0;background:var(--bg);
color:var(--ink);-webkit-font-smoothing:antialiased}
.page-wrap{max-width:1440px;margin:0 auto;padding:24px 28px 64px}
h1{font-size:1.3rem;font-weight:600;margin:0 0 4px;color:var(--ink)}
h2{font-size:1rem;font-weight:600;margin:28px 0 10px;color:var(--ink);border-bottom:1px solid var(--line);padding-bottom:6px}
table{border-collapse:collapse;font-size:12px;width:100%}
td,th{border:1px solid var(--line);padding:4px 8px;vertical-align:top;line-height:1.4}
th{background:var(--surface2);font-weight:500;text-align:left;font-size:11px;letter-spacing:.03em;color:var(--ink2)}
th:first-child,td:first-child{text-align:left}
tr:hover>td{background:rgba(0,0,0,.02)}
.P{background:var(--pass-bg);color:var(--pass)}
.F{background:var(--fail-bg);color:var(--fail);font-weight:600}
.W{background:var(--warn-bg);color:var(--warn)}
.N{color:var(--muted)}
.v{font-size:1rem;font-weight:600;padding:10px 0 14px;display:block}
.v b{font-size:1.1rem}
code{font-family:var(--mono);font-size:11px;background:var(--surface2);border-radius:3px;padding:1px 4px}
details{margin:2px 0}summary{cursor:pointer;font-size:11px;color:var(--ink2)}
.muted{color:var(--muted);font-size:11px}
.meta-table{margin-bottom:20px;border-radius:6px;overflow:hidden;border:1px solid var(--line)}
.meta-table th{width:160px}"""
ICON = {"PASS": "PASS", "FAIL": "FAIL", "NEUTRAL": "NEUTRAL"}


def e(s) -> str:
    return html.escape(redact(str(s)))


def grid(lock: dict, bad: set, widened: set) -> tuple[list, list, dict]:
    """(op, identity) -> list of cell keys. bad/widened: sets of cell keys."""
    g = defaultdict(list)
    for k in lock["cells"]:
        op, ident = k.split(" | ")[:2]
        g[(op, ident)].append(k)
    ops = sorted({o for o, _ in g})
    idents = list(dict.fromkeys(i for _, i in sorted(g, key=lambda x: x[1])))
    return ops, idents, g


def cell_html(lock: dict, keys: list, bad: set, widened: set, viol_by_cell: dict) -> str:
    ds = defaultdict(int)
    for k in keys:
        ds[lock["cells"][k]["decision"]] += 1
    cls = "F" if any(k in bad for k in keys) else "W" if any(k in widened for k in keys) else "P"
    label = {"F": "FAIL", "W": "CHANGED", "P": "PASS"}[cls]
    summ = " ".join(f"{d[0]}{n}" for d, n in sorted(ds.items()))
    rows = []
    for k in keys:
        c = lock["cells"][k]
        tgt, var = k.split(" | ")[2:]
        flag = " ⚠ " + "; ".join(e(v) for v in viol_by_cell.get(k, [])) if k in viol_by_cell else ""
        rows.append(f"<tr><td>{e(tgt)}</td><td>{e(var)}</td><td>{e(c['decision'])} {e(c['status'])}</td>"
                    f"<td>{e(', '.join(c['leaks']) or '-')}</td><td>{e(', '.join(c['db']) or '-')}</td>"
                    f"<td>{e(c['count'])}</td><td>{flag}</td></tr>")
    return (f'<td class="{cls}"><details><summary>{label} <span class="muted">{e(summ)}</span></summary>'
            "<table><tr><th>target</th><th>variant</th><th>decision</th><th>leaked canaries</th><th>DB changes</th>"
            f"<th>count</th><th>violation</th></tr>{''.join(rows)}</table></details></td>")


def render(lock: dict, title: str, base: dict | None = None, meta: dict | None = None) -> str:
    d = diff(base, lock) if base else None
    viols = d["new_violations"] if d else lock["violations"]
    viol_by_cell = defaultdict(list)
    for v in viols:
        viol_by_cell[v["cell"]].append(f'{v["rule"]}: {v["detail"]}')
    bad = set(viol_by_cell)
    widened = {c["cell"] for c in d["changes"] if c["class"] == "WIDENED"} if d else set()
    ops, idents, g = grid(lock, bad, widened)
    cov = lock["coverage"]
    L = ["<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>",
         "<meta http-equiv=Content-Security-Policy content=\"default-src 'none'; style-src 'unsafe-inline'\">",
         f"<title>{e(title)}</title><style>{CSS}</style></head><body><div class=page-wrap>", f"<h1>authz.lock: {e(title)}</h1>"]
    if d:
        L.append(f'<p class="v"><b class="{"F" if d["verdict"] == "FAIL" else "P"}">Verdict: {e(d["verdict"])}</b> '
                 f'· {len(d["new_violations"])} new invariant violations · '
                 f'{len(widened)} widened cells · {len(d["changes"])} changed cells'
                 + (f' · new operations: {e(", ".join(d["new_ops"]))}' if d["new_ops"] else "") + "</p>")
    else:
        L.append(f'<p class="v">Base lock: <b>{len(lock["violations"])} invariant violations</b></p>')
    h = lock.get("harness", {})
    facts = {"probes": lock["probes"], "probe time (s)": lock["elapsed_s"],
             "coverage": f'{cov["probed"]}/{cov["operations"]} operations',
             "never green (unprobed)": ", ".join(cov["unprobed"]) or "-",
             "harness": "valid" if h.get("valid") else f'INVALID: {"; ".join(h.get("failures", ["no gate results"]))}',
             **(meta or {})}
    L.append("<table>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in facts.items()) + "</table>")
    if viols:
        L += ["<h2>Invariant violations" + (" introduced by this PR" if d else "") + "</h2>",
              "<table><tr><th>rule</th><th>cell (op | identity | target | variant)</th><th>detail</th></tr>"]
        L += [f'<tr class="F"><td>{e(v["rule"])}</td><td><code>{e(v["cell"])}</code></td><td>{e(v["detail"])}</td></tr>'
              for v in viols[:300]]
        L.append("</table>")
    if d and widened:
        L += ["<h2>Access widened (lockfile diff)</h2><table><tr><th>cell</th><th>base</th><th>head</th></tr>"]
        fmt = lambda x: f'{x["decision"]} {x["status"]} leaks={x["leaks"] or "-"} db={x["db"] or "-"} count={x["count"]}'  # noqa
        L += [f'<tr class="W"><td><code>{e(c["cell"])}</code></td><td>{e(fmt(c["base"]))}</td><td>{e(fmt(c["head"]))}</td></tr>'
              for c in d["changes"] if c["class"] == "WIDENED"][:200]
        L.append("</table>")
    L += ["<h2>Identity × operation</h2>",
          "<p class=muted>PASS = no invariant violation in any probe of that pair; FAIL = at least one"
          + (" new" if d else "") + " violation; CHANGED = widened vs base without a violation. Letters: "
          "A=ALLOW D=DENY I=INCONCLUSIVE probe counts. Expand a cell for per-probe evidence (status, leaked "
          "canary owners, DB row changes with owner attribution); request/response bodies are not stored in the "
          "lock, and tokens/passwords are redacted.</p>",
          "<table><tr><th>operation</th>" + "".join(f"<th>{e(i)}</th>" for i in idents) + "</tr>"]
    for op in ops:
        L.append(f"<tr><th><code>{e(op)}</code></th>" + "".join(
            cell_html(lock, g[(op, i)], bad, widened, viol_by_cell) if (op, i) in g else '<td class="N">-</td>'
            for i in idents) + "</tr>")
    L += ["</table><p class=muted>Generated by report.py from the lockfile; the verdict is computed by "
          "authzlock.diff (deterministic, no LLM).</p></div></body></html>"]
    return "\n".join(L)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("lock", type=Path); ap.add_argument("out", type=Path)
    ap.add_argument("--base", type=Path); ap.add_argument("--title", default="")
    ap.add_argument("--meta", nargs="*", default=[])
    a = ap.parse_args()
    ld = lambda p: json.loads(p.read_text(encoding="utf-8"))  # noqa: E731
    page = render(ld(a.lock), a.title or a.lock.stem, ld(a.base) if a.base else None,
                  dict(m.split("=", 1) for m in a.meta))
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(page, encoding="utf-8")
