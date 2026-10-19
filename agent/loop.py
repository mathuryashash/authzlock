"""Minimal tool-calling loop: forced tool_choice, hard turn cap, `done` tool ends the run."""
import json

from agent import tf
from agent.tools import SCHEMAS

DONE = {"type": "function", "function": {"name": "done", "description": "Finish; summarize what you produced.",
        "parameters": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}}}


def run_agent(llm, tools, system: str, user: str, model: str = tf.SUPER, max_turns: int = 12,
              tool_choice="required", schemas=None) -> dict:
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    for turn in range(1, max_turns + 1):
        msg = llm.chat(model, messages, tools=(schemas or SCHEMAS) + [DONE], tool_choice=tool_choice).choices[0].message
        calls = msg.tool_calls or []
        if not calls:
            messages += [{"role": "assistant", "content": msg.content or ""},
                         {"role": "user", "content": "Respond only with a tool call."}]
            continue
        messages.append({"role": "assistant", "content": msg.content, "tool_calls": [
            {"id": c.id, "type": "function", "function": {"name": c.function.name,
                                                          "arguments": c.function.arguments}} for c in calls]})
        for c in calls:
            if c.function.name == "done":
                try:
                    summary = json.loads(c.function.arguments).get("summary", "")
                except ValueError:
                    summary = c.function.arguments
                return {"status": "done", "turns": turn, "summary": summary}
            messages.append({"role": "tool", "tool_call_id": c.id,
                             "content": tools.dispatch(c.function.name, c.function.arguments)})
    return {"status": "max_turns", "turns": max_turns, "summary": ""}
