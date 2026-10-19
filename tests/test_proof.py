"""Security #4: a regression test is a PROOF only if base passes, head fails with an AssertionError raised
inside the test (from JUnit XML, never exit codes), it names the finding's path and a canary, writes stayed
under tests/authz/, and the app source hash is unchanged."""
from proof import is_proof

PASS = '<testsuite><testcase classname="tests.authz.test_x" name="test_idor"/></testsuite>'
FAIL_ASSERT = ('<testsuite><testcase classname="tests.authz.test_x" name="test_idor">'
               '<failure message="AssertionError: assert 200 in (403, 404)">'
               'tests/authz/test_x.py:12: AssertionError</failure></testcase></testsuite>')
FAIL_IMPORT = ('<testsuite><testcase classname="tests.authz.test_x" name="test_idor">'
               '<error message="ImportError">E   ImportError: cannot import</error></testcase></testsuite>')
FAIL_ASSERT_OUTSIDE = ('<testsuite><testcase classname="tests.authz.test_x" name="test_idor">'
                       '<failure message="AssertionError">app/api/deps.py:40: AssertionError</failure>'
                       '</testcase></testsuite>')
SRC = 'def test_idor(client):\n    r = client.get(f"{API}/items/{item.id}")\n    assert "cnry-idor" not in r.text\n'
OK = dict(finding_path="/items/{id}", canary="cnry-idor", test_path="tests/authz/test_x.py",
          written=["tests/authz/test_x.py"], app_hash_before="h1", app_hash_after="h1")


def test_real_proof_accepted():
    assert is_proof(PASS, FAIL_ASSERT, SRC, **OK) == (True, [])


def test_pass_on_both_rejected():
    ok, why = is_proof(PASS, PASS, SRC, **OK)
    assert not ok and any("head" in w for w in why)


def test_import_error_on_head_rejected():
    assert not is_proof(PASS, FAIL_IMPORT, SRC, **OK)[0]


def test_assertion_outside_test_file_rejected():
    assert not is_proof(PASS, FAIL_ASSERT_OUTSIDE, SRC, **OK)[0]


def test_base_failure_rejected():
    assert not is_proof(FAIL_ASSERT, FAIL_ASSERT, SRC, **OK)[0]


def test_test_must_name_path_and_canary():
    assert not is_proof(PASS, FAIL_ASSERT, "def test_idor():\n    assert False\n", **OK)[0]


def test_writes_outside_tests_authz_rejected():
    assert not is_proof(PASS, FAIL_ASSERT, SRC, **dict(OK, written=["tests/authz/test_x.py", "app/api/deps.py"]))[0]


def test_app_source_change_rejected():
    assert not is_proof(PASS, FAIL_ASSERT, SRC, **dict(OK, app_hash_after="h2"))[0]


def test_empty_junit_rejected():
    assert not is_proof("<testsuite/>", FAIL_ASSERT, SRC, **OK)[0]
