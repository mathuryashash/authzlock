import report


def lock(cells, violations=(), probes=2):
    return {"cells": cells, "violations": list(violations), "probes": probes, "elapsed_s": 1.0,
            "coverage": {"operations": 1, "probed": 1, "unprobed": [], "unsupported": []},
            "harness": {"valid": True, "failures": []}}


def cell(decision="DENY", status=403, leaks=(), db=(), count=None):
    return {"decision": decision, "status": status, "leaks": list(leaks), "db": list(db), "count": count}


K = "GET /items/{id} | user_a | user_b | base"


def test_base_report_is_self_contained_and_escaped():
    evil = "GET /x<script>alert(1)</script> | user_a | user_b | base"
    page = report.render(lock({K: cell(), evil: cell(leaks=["eyJhbGciOi.eyJzdWIiOiJ4.sig123"])}), "t")
    assert "<script" not in page and "&lt;script&gt;" in page
    assert "default-src 'none'" in page and "http" not in page.split("</head>")[1]
    assert "eyJhbGciOi" not in page
    assert 'class="P"' in page and 'class="F"' not in page


def test_pr_report_marks_new_violation_and_verdict():
    base = lock({K: cell()})
    v = {"rule": "I1 read-isolation", "cell": K, "op": "GET /items/{id}", "identity": "user_a", "target": "user_b",
         "variant": "base", "detail": "user_a received data owned by user_b"}
    head = lock({K: cell("ALLOW", 200, leaks=["user_b"])}, [v])
    page = report.render(head, "pr", base=base, meta={"LLM $": "0.02"})
    assert "Verdict: FAIL" in page and 'class="F"' in page and "I1 read-isolation" in page
    assert "Access widened" in page and "LLM $" in page
    assert "Verdict: PASS" in report.render(base, "same", base=base)
