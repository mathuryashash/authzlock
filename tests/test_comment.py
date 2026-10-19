"""D4: PR comment renderer. Every string is untrusted (PR code shapes op names/details; LLM and Tavily text)."""
from comment import MAX_BYTES, esc, render

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF123_-xyz"
DIFF = {"verdict": "FAIL", "new_ops": ["GET /items/export"], "new_unprobed": [], "changes": [
    {"cell": "GET /items/ | user_a | - | base", "class": "WIDENED",
     "base": {"decision": "ALLOW", "status": 200, "count": 7}, "head": {"decision": "ALLOW", "status": 200, "count": 14}}],
    "new_violations": [
        {"rule": "I1 read-isolation", "op": "GET /items/{id}", "identity": "user_a", "target": "user_b",
         "variant": "base", "detail": "user_a received data | owned by user_b"},
        {"rule": "I1 read-isolation", "op": "GET /items/{id}", "identity": "user_b", "target": "user_a",
         "variant": "base", "detail": "x"}]}
PROOF = {"scenario": "pr-x", "status": "proven", "prove_runs": 2,
         "test": 'def test_x():\n    assert "cnry" not in r.text  # ``` @admin\n'}


def test_pr_comment_renders_fail_table_test_and_report_link():
    md = render(DIFF, proof=PROOF, root_cause="Owner check dropped.", report_url="https://x.github.io/r.html")
    assert "FAIL" in md and "I1 read-isolation" in md and "GET /items/{id}" in md
    assert "user_a → user_b, user_b → user_a" in md  # grouped per (rule, op)
    assert "7 → 14" in md  # count side channel
    assert "proven" in md and "def test_x" in md and "Owner check dropped." in md
    assert "https://x.github.io/r.html" in md


def test_escaping_of_untrusted_text():
    s = esc("a|b `c` <script> @team [x](javascript:alert(1)) ```")
    import re
    assert not re.search(r"(?<!\\)\|", s)  # pipes only as GFM-escaped \|
    for bad in ("`", "<script>", "@team", "](", ):
        assert bad not in s
    md = render(DIFF, proof=PROOF, root_cause="see](http://evil) @org/team <img src=x> | `x`")
    rc = md.split("Root cause")[1]
    assert "](" not in rc.split("\n```")[0] and "@org" not in rc and "<img" not in rc
    # the test source sits in a fence that its own backticks can't close
    fence = md.split("\ndef test_x")[0].rsplit("\n", 1)[-1]
    assert fence.startswith("~~~~")


def test_redacts_jwts_and_passwords():
    md = render(dict(DIFF, new_violations=[dict(DIFF["new_violations"][0], detail=f"token {JWT} password=hunter22")]),
                root_cause=f"Bearer {JWT}", proof=dict(PROOF, test=f'H = "{JWT}"\npassword = "s3cret!"\n'))
    assert JWT not in md and "hunter22" not in md and "s3cret!" not in md and "[redacted" in md


def test_capped_at_60kb():
    big = dict(DIFF, new_violations=[dict(DIFF["new_violations"][0], op=f"GET /x{i}", detail="d" * 500)
                                     for i in range(2000)])
    md = render(big, root_cause="r" * 100_000)
    assert len(md.encode()) <= MAX_BYTES and "truncated" in md


def test_pass_and_neutral():
    assert "No change in who can access what" in render({"verdict": "PASS", "changes": [], "new_violations": [],
                                                         "new_ops": [], "new_unprobed": []})
    assert "NEUTRAL" in render({"verdict": "NEUTRAL", "changes": [], "new_violations": [], "new_ops": [],
                                "new_unprobed": [], "harness_invalid": ["gate failed"]})
