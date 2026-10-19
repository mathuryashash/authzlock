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
