import json
from types import SimpleNamespace as NS

from agent import tf
from agent.loop import run_agent
from agent.tools import Tools


def tool_msg(name, args, id="c1"):
    call = NS(id=id, type="function", function=NS(name=name, arguments=json.dumps(args)))
    return NS(choices=[NS(message=NS(content=None, tool_calls=[call], role="assistant"),
                          finish_reason="tool_calls")])


class StubLLM:
    """Stands in for tf.LLM: returns scripted responses, or repeats the last one forever."""
    def __init__(self, script):
        self.script, self.requests = list(script), []

    def chat(self, model, messages, **kw):
        self.requests.append({"model": model, "messages": [dict(m) for m in messages], **kw})
        return self.script.pop(0) if len(self.script) > 1 else self.script[0]


def test_agent_loop_terminates_at_max_turns(tmp_path):
    llm = StubLLM([tool_msg("read_file", {"path": "nope.py"})])  # never calls done
    res = run_agent(llm, Tools(tmp_path), "sys", "go", max_turns=4)
    assert res["status"] == "max_turns" and res["turns"] == 4 and len(llm.requests) == 4


def test_loop_forces_tool_choice_and_uses_super_by_default(tmp_path):
    llm = StubLLM([tool_msg("done", {"summary": "s"})])
    run_agent(llm, Tools(tmp_path), "sys", "go", max_turns=3)
    req = llm.requests[0]
    assert req["model"] == tf.SUPER and req["tool_choice"] == "required"
    assert {t["function"]["name"] for t in req["tools"]} >= {"read_file", "write_file", "run", "done"}


def test_done_ends_loop_and_tool_results_are_fed_back(tmp_path):
    llm = StubLLM([tool_msg("write_file", {"path": "s.py", "content": "x"}, id="a"),
                   tool_msg("done", {"summary": "wrote seeder"}, id="b")])
    res = run_agent(llm, Tools(tmp_path), "sys", "go", max_turns=5)
    assert res == {"status": "done", "turns": 2, "summary": "wrote seeder"}
    fed = llm.requests[1]["messages"][-1]
    assert fed["role"] == "tool" and fed["tool_call_id"] == "a" and fed["content"].startswith("ok")


def test_text_reply_without_tool_call_is_nudged_not_crashed(tmp_path):
    text = NS(choices=[NS(message=NS(content="I think...", tool_calls=None, role="assistant"),
                          finish_reason="stop")])
    llm = StubLLM([text, tool_msg("done", {"summary": "ok"})])
    res = run_agent(llm, Tools(tmp_path), "sys", "go", max_turns=3)
    assert res["status"] == "done"
    assert llm.requests[1]["messages"][-1]["role"] == "user"
