"""Token Factory client: fixed base_url and models, retries, $ budget cap, JSONL cost log."""
import json
import os
import random
import time
from pathlib import Path

import openai

BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
SUPER = "nvidia/nemotron-3-super-120b-a12b"  # agent loop
ULTRA = "nvidia/Nemotron-3-Ultra-550b-a55b"  # root cause / fix
# USD per 1M tokens (input, output). Source: models.dev / mastra.ai listings, Oct 2026; re-check on the console.
PRICES = {SUPER: (0.30, 0.90), ULTRA: (1.00, 3.00)}
TRANSIENT = (openai.RateLimitError, openai.APITimeoutError, openai.APIConnectionError,
             openai.InternalServerError)


class BudgetExceeded(RuntimeError):
    pass


def make_openai_client(api_key: str | None = None) -> openai.OpenAI:
    return openai.OpenAI(base_url=BASE_URL, api_key=api_key or os.environ["NEBIUS_API_KEY"],
                         max_retries=0, timeout=120)


class LLM:
    def __init__(self, client=None, log_path: Path | str = ".authzlock/cost.jsonl", budget_usd: float = 1.0,
                 max_retries: int = 5, sleep=time.sleep):
        self.client = client or make_openai_client()
        self.log_path, self.budget_usd = Path(log_path), budget_usd
        self.max_retries, self.sleep = max_retries, sleep
        self.spent_usd, self.calls = 0.0, 0

    def chat(self, model: str, messages: list, **kw):
        if self.spent_usd >= self.budget_usd:
            raise BudgetExceeded(f"spent ${self.spent_usd:.4f} of ${self.budget_usd} budget")
        t = time.time()
        for attempt in range(self.max_retries + 1):
            try:
                r = self.client.chat.completions.create(model=model, messages=messages, **kw)
                break
            except TRANSIENT:
                if attempt == self.max_retries:
                    raise
                self.sleep(min(30, 2 ** attempt) + random.random())  # backoff + jitter (429s)
        pin, pout = PRICES.get(model, max(PRICES.values()))
        u = r.usage
        usd = (u.prompt_tokens * pin + u.completion_tokens * pout) / 1e6
        self.spent_usd += usd
        self.calls += 1
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as f:
            f.write(json.dumps({"model": model, "prompt_tokens": u.prompt_tokens,
                                "completion_tokens": u.completion_tokens, "usd": round(usd, 6),
                                "latency_s": round(time.time() - t, 3), "attempts": attempt + 1}) + "\n")
        return r
