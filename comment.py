"""D4: render a diff (+ optional proof, root cause, citations) as a GitHub PR comment.

Runs in workflow B on an artifact produced by PR code, so EVERY string is untrusted: escaped for Markdown
(|, backticks, <, @mentions, link syntax), JWTs and passwords redacted, output capped at 60 KB.

  python comment.py <diff.json> [regress_summary.json] [report_url] > comment.md
"""
import json
import re
import sys

MAX_BYTES = 60_000
JWT = re.compile(r"eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*")
PASSWORD = re.compile(r"(?i)(pass(?:word)?\w*[\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)")
ICON = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "NEUTRAL": "⚠️ NEUTRAL"}


def redact(s: str) -> str:
    return PASSWORD.sub(r"\1[redacted]", JWT.sub("[redacted JWT]", str(s)))


def esc(s) -> str:
    """Inline untrusted text: one line, no tables/code/HTML/mentions/links can be opened."""
    s = " ".join(redact(s).split())
    s = s.replace("\\", "\\\\").replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("](", "]\\(").replace("[", "\\[")
    return re.sub(r"@(?=\w)", "@\u200b", s)


def code(s) -> str:
    return f"<code>{esc(s)}</code>"  # esc() already made < and | inert; backticks can't break out


def fenced(src: str) -> str:
    longest = max((len(m) for m in re.findall(r"~+", src)), default=0)
    f = "~" * max(4, longest + 1)
    return f"{f}python\n{redact(src).replace('@', '@' + chr(0x200b))}\n{f}"


def render(d: dict, proof: dict | None = None, root_cause: str = "", cites: list | None = None,
           report_url: str = "") -> str:
    L = [f"## authz.lock: **{ICON.get(d.get('verdict'), 'NEUTRAL')}**", ""]
    if d.get("harness_invalid"):
        L += ["Harness invalid, so this PR can neither pass nor fail:", ""] + [f"- {esc(x)}" for x in d["harness_invalid"]]
    if d.get("new_ops"):
        L += ["**New operations** (judged by invariants): " + ", ".join(code(o) for o in d["new_ops"]), ""]
    groups = {}
    for v in d.get("new_violations", []):
        g = groups.setdefault((v["rule"], v["op"]), {"who": [], "detail": v.get("detail", "")})
        who = v.get("identity", "?") + (f" → {v['target']}" if v.get("target", "-") != "-" else "") \
            + (" (hostile body)" if v.get("variant") == "hostile" else "")
        if who not in g["who"]:
            g["who"].append(who)
    if groups:
        L += ["| Rule | Operation | Who | Example |", "|---|---|---|---|"]
        L += [f"| {esc(r)} | {code(op)} | {esc(', '.join(g['who']))} | {esc(g['detail'])} |"
              for (r, op), g in groups.items()]
        L.append("")
    counts = [c for c in d.get("changes", []) if c.get("class") == "WIDENED"
              and (c["head"].get("count") or 0) > (c["base"].get("count") or 0)]
    if counts:
        L += ["**Count side channel:** " + "; ".join(
            f"{code(c['cell'])} {c['base']['count']} → {c['head']['count']}" for c in counts), ""]
    if d.get("new_unprobed"):
        L += ["**Could not probe (never green):** " + ", ".join(code(o) for o in d["new_unprobed"]), ""]
    if d.get("verdict") == "PASS":
        L += ["No change in who can access what. No action needed.", ""]
    if proof:
        ok = proof.get("status") == "proven"
        L += [f"### Regression test: {'proven' if ok else 'unproven'} ({esc(proof.get('prove_runs', '?'))} prove runs"
              + ("; passes on base, fails on this PR)" if ok else f"; {esc('; '.join(proof.get('why', [])))})"), "",
              "<details><summary>tests/authz/test_regression.py (written by Nemotron, checked by JUnit)</summary>",
              "", fenced(proof.get("test", "")), "", "</details>", ""]
    if root_cause:
        L += ["### Root cause (Nemotron Ultra, advisory; does not affect the verdict)", "", esc(root_cause), ""]
    for f in cites or []:
        for c in f.get("citations", [])[:3]:
            if re.match(r"https://([a-z0-9-]+\.)*(owasp\.org|cwe\.mitre\.org)/[\w./#%-]*$", c.get("url", "")):
                L.append(f"> {esc(c.get('title', ''))}: {c['url']}")
    if report_url.startswith("https://"):
        L += ["", f"Full report: {esc(report_url)}"]
    out = "\n".join(L) + "\n"
    if len(out.encode()) > MAX_BYTES:
        out = out.encode()[:MAX_BYTES - 200].decode(errors="ignore") + "\n\n…truncated (60 KB cap); see the full report.\n"
    return out


if __name__ == "__main__":
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    rs = json.load(open(sys.argv[2], encoding="utf-8")) if len(sys.argv) > 2 and sys.argv[2] else {}
    r = next((x for x in rs.get("scenarios", []) if x.get("status") in ("proven", "unproven")), None)
    sys.stdout.write(render(d, proof=r, root_cause=(r or {}).get("root_cause", ""),
                            cites=(r or {}).get("citations"), report_url=sys.argv[3] if len(sys.argv) > 3 else ""))
