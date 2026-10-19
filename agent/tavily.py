"""Tavily angle 1: one OWASP/CWE search per FAIL finding. Output is quoted data for report prose ONLY;
it is computed after the verdict and nothing in authzlock.py reads it (security #5)."""
import json
import os
import re
import urllib.request

DOMAINS = ["owasp.org", "cwe.mitre.org"]
QUERY = {"I1": "broken object level authorization IDOR", "I2": "unauthenticated data modification",
         "I3": "broken object level authorization write", "I4": "mass assignment privilege escalation",
         "I5": "broken authentication JWT", "I6": "sensitive data exposure email"}


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, json.dumps(payload).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def _allowed(url: str) -> bool:
    return any(re.match(rf"https://([a-z0-9-]+\.)*{re.escape(d)}/", url) for d in DOMAINS)


def cite(diff: dict, api_key: str | None = "", post=_post) -> list[dict]:
    api_key = os.environ.get("TAVILY_API_KEY") if api_key == "" else api_key
    if diff.get("verdict") != "FAIL" or not api_key:
        return []
    out, seen = [], set()
    for v in diff["new_violations"]:
        key = (v["rule"].split()[0], v["op"])
        if key in seen:
            continue
        seen.add(key)
        r = post("https://api.tavily.com/search", {
            "api_key": api_key, "query": f"{QUERY.get(key[0], v['rule'])} OWASP API security CWE",
            "include_domains": DOMAINS, "max_results": 3, "search_depth": "basic"})
        out.append({"rule": v["rule"], "op": v["op"],
                    "citations": [{"title": str(x.get("title", ""))[:120], "url": x["url"],
                                   "snippet": str(x.get("content", ""))[:300]}
                                  for x in r.get("results", []) if _allowed(str(x.get("url", "")))]})
    return out


def _quote(s: str) -> str:
    return re.sub(r"[<>`|\[\]]", "", " ".join(s.split()))


def render(cites: list[dict]) -> str:
    lines = []
    for f in cites:
        lines.append(f"**References for {_quote(f['rule'])} on `{_quote(f['op'])}`** (external text, quoted):")
        for c in f["citations"]:
            lines.append(f"> {_quote(c['title'])} ({c['url']}): {_quote(c['snippet'])}")
    return "\n".join(lines)
