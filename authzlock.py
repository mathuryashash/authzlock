"""
authz.lock — build an executable access-control lockfile for a FastAPI app and diff it per PR.

  python authzlock.py lock  --checkout <repo checkout> --out authz.lock.json
  python authzlock.py diff  --base authz.lock.json --head head.lock.json --out report.md
  python authzlock.py pr    --repo <git repo> --base <ref> --head <ref> --workdir <dir>

Verdict path is deterministic: no LLM decides anything here.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import probe_lib

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.json"
DENY_STATUSES = "any 4xx except none"  # documented rule, see decide()


def decide(status: int, foreign_leak: bool, foreign_db: bool) -> str:
    """ALLOW = 2xx/3xx, or any foreign leak, or any foreign DB change.
    INCONCLUSIVE = 5xx. DENY = every other 4xx (the template uses 400/401/403/404)."""
    if 200 <= status < 400 or foreign_leak or foreign_db:
        return "ALLOW"
    if status >= 500:
        return "INCONCLUSIVE"
    return "DENY"


def build_lock(raw: dict, man: dict) -> dict:
    invalid = set(man["invalid_identities"])
    privileged = set(man["privileged_identities"])
    public = set(man["public_operations"])
    exceptions = {(e["op"], e["identity"], e["allow"]) for e in man["exceptions"]}
    cells, violations, unsupported = {}, [], []
    ok_ops, all_ops = set(), set()

    for r in raw["results"]:
        if "unsupported" in r:
            unsupported.append(r["op"])
            continue
        op, ident = r["op"], r["identity"]
        all_ops.add(op)
        self_role = ident if ident not in invalid else ("inactive" if ident == "inactive" else None)
        rel = lambda role: "self" if role == self_role else role  # noqa: E731
        foreign_leaks = [x for x in r["leaks"] if x != self_role]
        foreign_db = [e for e in r["db"] if e["owner"] != self_role or e.get("new_owner")]
        decision = decide(r["status"], bool(foreign_leaks) and ident not in privileged,
                          bool(foreign_db))
        if decision == "ALLOW" and 200 <= r["status"] < 300 and ident not in invalid:
            ok_ops.add(op)
        key = f'{op} | {ident} | {r["target"]} | {r["variant"]}'
        cells[key] = {
            "decision": decision,
            "leaks": sorted(rel(x) for x in r["leaks"]),
            "db": sorted(f'{e["op"]}:{e["table"]}:{rel(e["owner"])}'
                         + (f'->{rel(e["new_owner"])}' if e.get("new_owner") else "")
                         + (f'[priv:{",".join(e["privilege_change"])}]' if e.get("privilege_change") else "")
                         + ("[privileged]" if e.get("privileged_insert") else "")
                         for e in r["db"]),
            "count": r["count"],
            "status": r["status"],
        }

        def viol(rule, detail):
            violations.append({"rule": rule, "cell": key, "op": op, "identity": ident,
                               "target": r["target"], "variant": r["variant"], "detail": detail})

        exc = lambda kind: (op, ident, kind) in exceptions or (op, "*", kind) in exceptions  # noqa: E731
        # I1 read isolation
        if ident not in privileged and foreign_leaks:
            viol("I1 read-isolation", f"{ident} received data owned by {', '.join(foreign_leaks)}")
        # I6 out-of-band leak
        if r["smtp_leaks"]:
            viol("I6 out-of-band", f"email to someone else contained data of {', '.join(r['smtp_leaks'])}")
        for e in r["db"]:
            owner = e["owner"]
            if ident in privileged:
                continue
            if e.get("privilege_change") or e.get("privileged_insert"):
                viol("I4 privilege", f"{ident} changed privilege columns {e.get('privilege_change') or 'is_superuser'} "
                                     f"on a {e['table']} row owned by {rel(owner)}")
            if e["op"] == "insert" and e["table"] == "user":
                if not exc("insert_user_nonprivileged") or e.get("privileged_insert"):
                    viol("I3 write-isolation", f"{ident} created a new user account")
            elif e["op"] == "insert":
                if owner != self_role:
                    viol("I3 write-isolation", f"{ident} created a {e['table']} row owned by {owner}")
            elif owner != self_role or e.get("new_owner"):
                viol("I3 write-isolation",
                     f"{ident} {e['op']}d a {e['table']} row owned by {rel(owner)}"
                     + (f" (ownership moved to {rel(e['new_owner'])})" if e.get("new_owner") else ""))
            elif ident in invalid:
                viol("I2 invalid-identity-write", f"{ident} modified data")
        # I5 authentication: invalid identities never get ALLOW on non-public operations
        if ident in invalid and op not in public and decision == "ALLOW":
            viol("I5 authn", f"{ident} was allowed (HTTP {r['status']}) on a non-public operation")

    coverage = {"operations": len(all_ops) + len(set(unsupported)), "probed": len(ok_ops),
                "unprobed": sorted(all_ops - ok_ops), "unsupported": sorted(set(unsupported))}
    return {"format": "authz.lock/v0", "tag": raw["tag"], "probes": raw["probes"],
            "elapsed_s": raw["elapsed_s"], "coverage": coverage, "cells": cells,
            "violations": violations, "harness": seeder_gates(raw, man)}


def seeder_gates(raw: dict, man: dict) -> dict:
    """Security #3: >=2 non-privileged owners with canaried rows (counted by the worker from the seed DB,
    not claimed by the seeder), and each one gets ALLOW + its own canary back on some request."""
    skip = set(man["privileged_identities"]) | set(man["invalid_identities"])
    owners = [r for r, v in raw.get("roles", {}).items() if r not in skip and v.get("canaried_rows", 0) > 0]
    fails = [] if len(owners) >= 2 else [f"need >=2 non-privileged owners with canaried rows, got {owners}"]
    for o in owners:
        if not any(r.get("identity") == o and 200 <= r.get("status", 0) < 300 and o in r.get("leaks", [])
                   for r in raw["results"]):
            fails.append(f"{o}: no self-read returned ALLOW with its own canary")
    for role, spec in man["identities"].items():  # the seeder must create what the manifest declares
        flags = raw.get("roles", {}).get(role, {}).get("flags", {})
        want = {"is_superuser": "True" if spec.get("superuser") else None,
                "is_active": "False" if spec.get("is_active") is False else None}
        fails += [f"{role}: seeded user row has {c}={flags[c]}, manifest wants {v}"
                  for c, v in want.items() if v and c in flags and flags[c] != v]
    return {"valid": not fails, "failures": fails}


# The worker imports PR code and LLM-written seeders: it must never see API keys (security #1).
WORKER_ENV_ALLOW = ("PATH", "DATABASE_URL", "SMTP_PORT", "HOME", "USERPROFILE", "LANG", "SYSTEMROOT", "TEMP", "TMP",
                    "AUTHZ_PROFILE", "AUTHZ_DEBUG")


def worker_env() -> dict:
    env = {k: os.environ[k] for k in WORKER_ENV_ALLOW if k in os.environ}
    return dict(env, TZ="UTC", PYTHONWARNINGS="ignore", PYTHONUTF8="1")


def run_worker(checkout: Path, tag: str, out_raw: Path, smtp_port: int, manifest: Path = MANIFEST,
               seeder: Path | None = None, prof: dict | None = None) -> dict:
    prof = prof or probe_lib.profile()
    checkout = Path(checkout).absolute()  # cwd below; absolute(), not resolve(): keep the venv symlink
    backend = checkout / prof["cwd"]
    venv_py = next((p for p in (checkout / ".venv" / "bin" / "python", checkout / ".venv" / "Scripts" / "python.exe")
                    if p.exists()), Path(os.environ.get("AUTHZ_PY", sys.executable)))
    env = worker_env()
    argv = [str(venv_py), str(HERE / "probe_worker.py"), "--manifest", str(Path(manifest).resolve()),
            "--out", str(Path(out_raw).resolve()), "--tag", tag, "--smtp-port", str(smtp_port),
            "--pg", os.environ.get("AUTHZ_PG", "postgresql://postgres@localhost:5432/postgres"),
            "--profile-json", json.dumps(prof), "--dotenv", str(checkout / ".env")]
    if seeder:
        argv += ["--seeder", str(Path(seeder).resolve())]
    p = subprocess.run(argv, cwd=backend, env=env, capture_output=True, text=True, timeout=1800)
    if p.returncode != 0:  # root cause first: the agent only sees the tail, and asyncio shutdown noise buries it
        raise SystemExit(f"worker failed for {tag}: {root_error(p.stderr)}\n{p.stderr[-3000:]}")
    return json.loads(Path(out_raw).read_text())


def root_error(stderr: str) -> str:
    """Final line of the first traceback (later ones are interpreter-shutdown noise), else the last line."""
    tb = stderr.split("Traceback (most recent call last):")
    if len(tb) > 1:
        lines = [ln for ln in tb[1].splitlines() if ln.strip() and not ln.startswith(" ")]
        if lines:
            return lines[-1] if not lines[-1].startswith("Exception ignored") else lines[0]
    return (stderr.strip().splitlines() or [""])[-1]


def cmd_lock(checkout: Path, out: Path, tag: str, smtp_port: int = 1025, manifest: Path = MANIFEST,
             seeder: Path | None = None) -> dict:
    man = json.loads(Path(manifest).read_text())
    raw = run_worker(checkout, tag, out.with_suffix(".raw.json"), smtp_port, manifest, seeder)
    lock = build_lock(raw, man)
    out.write_text(json.dumps(lock, indent=1, sort_keys=True))
    return lock


# ------------------------------------------------------------------------------ diff
def classify(b: dict, h: dict) -> str | None:
    if b["decision"] == h["decision"] and b["leaks"] == h["leaks"] and b["db"] == h["db"] \
            and b["count"] == h["count"]:
        return None
    if h["decision"] == "INCONCLUSIVE" or b["decision"] == "INCONCLUSIVE":
        return "INCONCLUSIVE"
    new_leaks = set(h["leaks"]) - set(b["leaks"]) - {"self"}
    new_db = set(h["db"]) - set(b["db"])
    foreign_new_db = {d for d in new_db if ":self" not in d or "->" in d or "priv" in d}
    count_up = (h["count"] or 0) > (b["count"] or 0)
    if (b["decision"] == "DENY" and h["decision"] == "ALLOW") or new_leaks or foreign_new_db or count_up:
        return "WIDENED"
    if b["decision"] == "ALLOW" and h["decision"] == "DENY":
        return "NARROWED"
    return "CHANGED"


def diff(base: dict, head: dict) -> dict:
    bc, hc = base["cells"], head["cells"]
    op_of = lambda k: k.split(" | ")[0]  # noqa: E731
    base_ops, head_ops = {op_of(k) for k in bc}, {op_of(k) for k in hc}
    changes = []
    for k in sorted(set(bc) & set(hc)):
        c = classify(bc[k], hc[k])
        if c:
            changes.append({"cell": k, "class": c, "base": bc[k], "head": hc[k]})
    sig = lambda v: (v["rule"], v["cell"])  # noqa: E731
    base_v = {sig(v) for v in base["violations"]}
    new_violations = [v for v in head["violations"] if sig(v) not in base_v]
    fixed_violations = [v for v in base["violations"] if sig(v) not in {sig(x) for x in head["violations"]}]
    new_ops = sorted(head_ops - base_ops)
    removed_ops = sorted(base_ops - head_ops)
    new_unprobed = sorted(set(head["coverage"]["unprobed"]) - set(base["coverage"]["unprobed"]))
    widened = [c for c in changes if c["class"] == "WIDENED"]
    harness_invalid = [f"{side}: {f}" for side, lk in (("base", base), ("head", head))
                       for f in lk.get("harness", {"failures": ["no seeder gate results"]})["failures"]]
    if harness_invalid:  # a vacuous harness can neither pass nor fail a PR
        verdict = "NEUTRAL"
    elif new_violations or widened:
        verdict = "FAIL"
    elif changes or new_unprobed or head["coverage"]["unsupported"]:
        verdict = "NEUTRAL"
    else:
        verdict = "PASS"
    return {"verdict": verdict, "changes": changes, "new_violations": new_violations,
            "fixed_violations": fixed_violations, "new_ops": new_ops, "removed_ops": removed_ops,
            "new_unprobed": new_unprobed, "harness_invalid": harness_invalid}



def render_report(title: str, base: dict, head: dict, d: dict) -> str:
    icon = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "NEUTRAL": "⚠️ NEUTRAL"}[d["verdict"]]
    L = [f"## authz.lock — {title}", "", f"**Verdict: {icon}**", "",
         f"Probes: base {base['probes']} ({base['elapsed_s']}s) · head {head['probes']} ({head['elapsed_s']}s) · "
         f"coverage {head['coverage']['probed']}/{head['coverage']['operations']} operations"]
    if d["new_ops"]:
        L += ["", "**New operations** (no baseline; judged by invariants): " + ", ".join(f"`{o}`" for o in d["new_ops"])]
    if d["new_violations"]:
        L += ["", "### Invariant violations introduced by this PR", "",
              "| Rule | Operation | Who | Example evidence |", "|---|---|---|---|"]
        groups = {}
        for v in d["new_violations"]:
            g = groups.setdefault((v["rule"], v["op"]), {"who": [], "example": v})
            who = v["identity"] + (f' → {v["target"]}' if v["target"] != "-" else "") \
                + (" (hostile body)" if v["variant"] == "hostile" else "")
            if who not in g["who"]:
                g["who"].append(who)
        for (rule, op), g in groups.items():
            ex = g["example"]
            L.append(f'| {rule} | `{op}` | {", ".join(g["who"])} | {ex["detail"]} |')
    widened = [c for c in d["changes"] if c["class"] == "WIDENED"]
    other = [c for c in d["changes"] if c["class"] != "WIDENED"]
    if widened:
        L += ["", "### Access widened (lockfile diff)", "", "| Cell | Base | Head |", "|---|---|---|"]
        for c in widened[:40]:
            fmt = lambda x: f'{x["decision"]} {x["status"]} leaks={x["leaks"] or "-"} db={x["db"] or "-"} count={x["count"]}'  # noqa
            L.append(f'| `{c["cell"]}` | {fmt(c["base"])} | {fmt(c["head"])} |')
        if len(widened) > 40:
            L.append(f"| … {len(widened) - 40} more | | |")
    if other:
        L += ["", f"### Other lockfile changes ({len(other)})", ""]
        for c in other[:15]:
            L.append(f'- {c["class"]}: `{c["cell"]}` {c["base"]["decision"]} {c["base"]["status"]} → '
                     f'{c["head"]["decision"]} {c["head"]["status"]}')
    if d["new_unprobed"]:
        L += ["", "**Could not probe (never green):** " + ", ".join(f"`{o}`" for o in d["new_unprobed"])]
    if d["verdict"] == "PASS":
        L += ["", "No change in who can access what. No human action needed."]
    if d["verdict"] == "FAIL":
        L += ["", "### Maintainer decision", "",
              "Only a maintainer knows whether this was intended. In the GitHub Action (not built in this "
              "prototype) the check stays red until a maintainer replies `/authz accept <decision-id>`, which "
              "updates authz.lock. A runnable regression test for these findings is generated separately "
              "(`<scenario>.test_authz_regressions.py`) and proven to pass on base and fail on this PR."]
    return "\n".join(L) + "\n"


def cmd_pr(repo: Path, base_ref: str, head_ref: str, workdir: Path, env_file: Path) -> dict:
    workdir, repo = workdir.resolve(), repo.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    trees = {}
    for label, ref in (("base", base_ref), ("head", head_ref)):
        tree = workdir / f"wt_{label}_{ref.replace('/', '_')}"
        if tree.exists():
            subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(tree)],
                           capture_output=True)
        subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(tree), ref],
                       check=True, capture_output=True)
        shutil.copy(env_file, tree / ".env")
        venv = repo / ".venv"
        if venv.exists() and not (tree / ".venv").exists():
            (tree / ".venv").symlink_to(venv)
        trees[label] = tree
    t = time.time()
    with ThreadPoolExecutor(2) as ex:  # base and head in parallel (separate DBs + SMTP ports)
        fb = ex.submit(cmd_lock, trees["base"], workdir / f"{base_ref}.lock.json", f"b_{base_ref}", 1025)
        fh = ex.submit(cmd_lock, trees["head"], workdir / f"{head_ref}.lock.json", f"h_{head_ref}", 1026)
        base, head = fb.result(), fh.result()
    d = diff(base, head)
    d["wall_s"] = round(time.time() - t, 1)
    report = render_report(f"{head_ref} vs {base_ref}", base, head, d)
    (workdir / f"{head_ref}.report.md").write_text(report)
    (workdir / f"{head_ref}.diff.json").write_text(json.dumps(d, indent=1))
    for tree in trees.values():
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(tree)],
                       capture_output=True)
    return {"verdict": d["verdict"], "wall_s": d["wall_s"], "report": report, "diff": d,
            "base": base, "head": head}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("lock"); a.add_argument("--checkout", type=Path, required=True)
    a.add_argument("--out", type=Path, required=True); a.add_argument("--tag", default="lock")
    a.add_argument("--manifest", type=Path, default=MANIFEST); a.add_argument("--seeder", type=Path)
    b = sub.add_parser("diff"); b.add_argument("--base", type=Path, required=True)
    b.add_argument("--head", type=Path, required=True); b.add_argument("--out", type=Path)
    c = sub.add_parser("pr"); c.add_argument("--repo", type=Path, required=True)
    c.add_argument("--base", required=True); c.add_argument("--head", required=True)
    c.add_argument("--workdir", type=Path, required=True); c.add_argument("--env-file", type=Path, required=True)
    ns = ap.parse_args()
    if ns.cmd == "lock":
        lk = cmd_lock(ns.checkout, ns.out, ns.tag, manifest=ns.manifest, seeder=ns.seeder)
        print(json.dumps({"coverage": lk["coverage"], "harness": lk["harness"],
                          "violations": [f'{v["rule"]}: {v["cell"]}' for v in lk["violations"]][:20]}, indent=1))
    elif ns.cmd == "diff":
        bl, hl = json.loads(ns.base.read_text()), json.loads(ns.head.read_text())
        d = diff(bl, hl)
        rep = render_report(f"{ns.head.name} vs {ns.base.name}", bl, hl, d)
        (ns.out.write_text(rep) if ns.out else print(rep))
    else:
        res = cmd_pr(ns.repo, ns.base, ns.head, ns.workdir, ns.env_file)
        print(res["report"])
        sys.exit({"PASS": 0, "NEUTRAL": 78, "FAIL": 1}[res["verdict"]])
