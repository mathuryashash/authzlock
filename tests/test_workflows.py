"""Security #2: workflow split. A (pull_request) has no secrets and read-only contents; B (workflow_run) only
renders + comments; the agent (Nebius key) never runs on PR events. All actions pinned by full SHA."""
import re
from pathlib import Path

WF = Path(__file__).resolve().parent.parent / ".github" / "workflows"


def read(name):
    return (WF / name).read_text()


def test_all_workflows_pinned_least_privilege_no_pull_request_target():
    files = sorted(WF.glob("*.yml"))
    assert {f.name for f in files} == {"authz-probe.yml", "authz-comment.yml", "authz-agent.yml"}
    for f in files:
        s = f.read_text()
        assert "pull_request_target" not in s
        assert re.search(r"^permissions:", s, re.M), f.name
        for use in re.findall(r"uses:\s*(\S+)", s):
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", use), (f.name, use)


def test_probe_workflow_has_no_secrets_and_reads_policy_from_base():
    s = read("authz-probe.yml")
    assert re.search(r"^on:\s*\n\s+pull_request:", s, re.M)
    assert "secrets." not in s and "NEBIUS" not in s and "TAVILY" not in s
    assert re.search(r"^permissions:\s*\n\s+contents: read\s*$", s, re.M)
    assert "github.event.pull_request.base.sha" in s  # engine, manifest, seeder come from base
    assert "diff.json" in s


def test_probe_build_does_not_check_out_side_branches_in_target():
    # git refuses `worktree add` for a branch already checked out in target/ (first live run failed so)
    build = read("authz-probe.yml").split("Build target app", 1)[1].split("- name:", 1)[0]
    assert "git checkout" not in build and "worktree add" in build


def test_comment_skips_failed_probe_runs():
    assert "github.event.workflow_run.conclusion == 'success'" in read("authz-comment.yml")


def test_comment_workflow_only_renders_artifact():
    s = read("authz-comment.yml")
    assert "workflow_run:" in s and "pull-requests: write" in s
    assert "secrets.NEBIUS" not in s and "secrets.TAVILY" not in s
    assert "comment.py" in s and "github.event.workflow_run.pull_requests[0].number" in s
    assert "actions/checkout" in s and "ref:" not in s  # default branch only: never PR code


def test_agent_workflow_never_on_pull_requests():
    s = read("authz-agent.yml")
    on = s.split("on:", 1)[1].split("permissions:", 1)[0]
    assert "pull_request" not in on and "push:" in on and "workflow_dispatch" in on
