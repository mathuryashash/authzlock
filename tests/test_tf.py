import json
import os
import re
from types import SimpleNamespace as NS

import pytest

from agent import tf


def fake_response(prompt=100, completion=50, content="hi", tool_calls=None):
    msg = NS(content=content, tool_calls=tool_calls, role="assistant")
    return NS(choices=[NS(message=msg, finish_reason="stop")],
              usage=NS(prompt_tokens=prompt, completion_tokens=completion))


class StubCompletions:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def create(self, **kw):
        self.calls.append(kw)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def stub_client(responses):
    comp = StubCompletions(responses)
    return NS(chat=NS(completions=comp)), comp


def test_tf_client_uses_nebius_base_url():
    c = tf.make_openai_client(api_key="dummy")
    assert str(c.base_url) == "https://api.tokenfactory.nebius.com/v1/"
    assert re.match(r"^nvidia/", tf.SUPER) and re.match(r"^nvidia/", tf.ULTRA)


def test_cost_logger_records_model_tokens_usd_latency(tmp_path):
    client, _ = stub_client([fake_response(1000, 500), fake_response(2000, 0)])
    log = tmp_path / "cost.jsonl"
    llm = tf.LLM(client=client, log_path=log, budget_usd=1.0)
    llm.chat(tf.SUPER, [{"role": "user", "content": "x"}])
    llm.chat(tf.ULTRA, [{"role": "user", "content": "y"}])
    rows = [json.loads(l) for l in log.read_text().splitlines()]
    assert [r["model"] for r in rows] == [tf.SUPER, tf.ULTRA]
    assert rows[0]["prompt_tokens"] == 1000 and rows[0]["completion_tokens"] == 500
    assert rows[0]["usd"] > 0 and rows[0]["latency_s"] >= 0
    assert llm.spent_usd == pytest.approx(sum(r["usd"] for r in rows))
    assert llm.calls == 2


def test_budget_cap_refuses_call_once_spent(tmp_path):
    client, comp = stub_client([fake_response(10**7, 10**7), fake_response()])
    llm = tf.LLM(client=client, log_path=tmp_path / "c.jsonl", budget_usd=0.01)
    llm.chat(tf.SUPER, [{"role": "user", "content": "x"}])
    with pytest.raises(tf.BudgetExceeded):
        llm.chat(tf.SUPER, [{"role": "user", "content": "x"}])
    assert len(comp.calls) == 1


def test_retries_on_transient_error_then_succeeds(tmp_path):
    client, comp = stub_client([make_transient(), make_transient(), fake_response()])
    llm = tf.LLM(client=client, log_path=tmp_path / "c.jsonl", sleep=lambda s: None)
    r = llm.chat(tf.SUPER, [{"role": "user", "content": "x"}])
    assert r.choices[0].message.content == "hi" and len(comp.calls) == 3


def test_gives_up_after_max_retries(tmp_path):
    client, comp = stub_client([make_transient() for _ in range(10)])
    llm = tf.LLM(client=client, log_path=tmp_path / "c.jsonl", sleep=lambda s: None, max_retries=3)
    with pytest.raises(tf.TRANSIENT):
        llm.chat(tf.SUPER, [{"role": "user", "content": "x"}])
    assert len(comp.calls) == 4


def make_transient():
    import openai
    return openai.APITimeoutError(request=None)


needs_key = pytest.mark.skipif(not os.environ.get("NEBIUS_API_KEY"), reason="NEBIUS_API_KEY not set")


@pytest.mark.live
@needs_key
def test_live_tf_smoke(tmp_path):
    llm = tf.LLM(log_path=tmp_path / "c.jsonl", budget_usd=0.05)
    r = llm.chat(tf.SUPER, [{"role": "user", "content": "Reply with the word ok."}], max_tokens=200)
    assert r.choices[0].message.content
    tools = [{"type": "function", "function": {"name": "echo", "description": "echo text",
              "parameters": {"type": "object", "properties": {"text": {"type": "string"}},
                             "required": ["text"]}}}]
    r = llm.chat(tf.SUPER, [{"role": "user", "content": "Call echo with text=hello"}], tools=tools,
                 tool_choice={"type": "function", "function": {"name": "echo"}}, max_tokens=300)
    call = r.choices[0].message.tool_calls[0]
    assert call.function.name == "echo" and "text" in json.loads(call.function.arguments)
