# Feedback log: Nebius Token Factory, AI Cloud, NVIDIA Nemotron

This is a running log of friction and wins, kept while building authz.lock for the Nebius x NVIDIA Global AI Hackathon. Each entry covers:
- what it was used for
- what worked
- what needs work
- time to hello world
- whether I would build with it again

## 2026-10-19: onboarding (before the hackathon starts)

- **Billing with an Indian card.** Indian cards appear to be declined at Token Factory billing. Other participants have reported the same thing on the forum/Discord. Indian cards need RBI e-mandate / AFA for recurring international charges, so a card that works elsewhere can still fail here. Because of this I have **no API key yet**, and for a hackathon that requires TF inference, this is the #1 blocker. Suggested fixes:
  - a promo code or credit grant that doesn't need a card;
  - a prepaid credit top-up instead of a recurring mandate;
  - a clear error message that says which card types are accepted.
- **Sandboxes beta is gated.** Access to Token Factory Sandboxes needs a request or waitlist, with no published turnaround time. I planned around this: Sandboxes is used only for test proofs on base/head checkpoints, with a go/no-go on Oct 22. Publishing an expected approval time, or granting hackathon participants access automatically, would let builders commit to it.
- **SDK Python pin.** The `contree-sdk` docs pin Python 3.12, while my target app needs Python 3.14. I'll have to run the SDK in its own venv.
- **Docs / OpenAI compatibility.** Not yet verified. The plan is to use the `openai` package with `base_url=https://api.tokenfactory.nebius.com/v1/`. Time to hello world: _pending key_.
- **Model IDs are case-sensitive and inconsistent:** `nvidia/nemotron-3-super-120b-a12b` is lowercase, while `nvidia/Nemotron-3-Ultra-550b-a55b` is mixed case. Third-party catalogs list both spellings. To be verified against `/v1/models` once there's a key.
- **Pricing source.** I could only find per-token prices for Super ($0.30/$0.90 per M) and Ultra ($1/$3 per M) on third-party aggregators. A machine-readable price list on `/v1/models` would make cost caps reliable.

## 2026-10-20: first real agent run (D2)

- **Used for:** Nemotron 3 Super (`nvidia/nemotron-3-super-120b-a12b`) as a tool-calling agent that reads a FastAPI app's OpenAPI + source and writes a seeder (Python) and a policy/param manifest (JSON).
- **What worked:** OpenAI SDK with `base_url` worked unchanged; `tool_choice="required"` was honoured on every turn (14/14 calls returned a tool call, 0 malformed JSON arguments). The agent produced a working seeder on the first try, using the app's own `crud`/models, and followed the "every value carries the canary" contract. Latency 2–5 s per turn at 10–16k prompt tokens. Whole onboarding: 14 calls, 147k prompt / 8k completion tokens, **$0.051** (at the placeholder prices), 2m17s.
- **Needs work:** (1) Usage objects don't report cached prompt tokens, and agent loops resend a growing history, so prompt caching visibility would matter a lot for cost. (2) Prices are still not machine-readable from the API, so the $ cap depends on numbers copied by hand. (3) The model did redundant work: after a green run it re-read the OpenAPI and rewrote the manifest twice before calling `done`. That's a prompt issue on my side, but a "stop when the tool says success" behaviour would cut ~30% of tokens.
- **Would build with it again:** yes; tool calling on Super is reliable enough that the D1 fallback to Ultra for the loop was not needed.


## 2026-10-20: regression-test agent (D3) and Ultra root cause

- **Used for:** Nemotron Super writes a pytest regression test per finding and repairs it against a fixed `prove` tool (base/head JUnit). Nemotron Ultra writes one root-cause paragraph per FAIL, using Tavily OWASP/CWE results as quoted data.
- **What worked:** On the IDOR PR, Super read the app's conftest/test utils, wrote an idiomatic test with the canary, and reached a valid proof (pass on base, AssertionError on head). It took 16 turns and 3 prove runs. The whole run (Super + Ultra) cost $0.032. Ultra named the exact dropped lines and cited CWE-639 and API1:2023 correctly.
- **Friction:** (1) Ultra returns its reasoning inline, so I strip everything before `</think>`. A documented reasoning on/off flag would avoid wasted output tokens. (2) The model tried `read_file` on a directory twice. A `list_dir` tool would be cheaper than the errors. (3) My own bug: I compared base and head app hashes, which made a correct proof show as "app source changed". Each side now checks its own before/after.
