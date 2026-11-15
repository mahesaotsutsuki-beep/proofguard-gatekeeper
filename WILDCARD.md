# ProofGuard — a wallet guard that proves every decision it makes

## The problem

AI agents are starting to move money. A treasury agent, a payment agent, a
trading agent: each one makes approve/reject calls all day, and the only
record of *why* is usually a log line the agent wrote about itself. If the
agent is buggy, compromised, or just wrong, the log still says "checked".

ProofGuard is a guard service that sits between an agent and its wallet.
Before any transfer executes, the guard checks the transfer against the
wallet owner's policy — and produces a zero-knowledge proof that the check
actually happened, with the right inputs, and the right outcome. The proof
is verifiable by anyone, against a public verification key, without trusting
the guard, the agent, or the machine either runs on.

## What it checks

Every transfer request is verified against the owner's registered policy:

- **Verification-key match** — the proof attesting to the transfer must be
  built against the owner's registered key, not a substituted one.
- **Balance threshold** — the public balance must meet the policy minimum.
- **Proof freshness** — a proof reference can only be used once.
- **Expiry** — the policy's expiry block must be in the future.
- **Recipient match** — the transfer's recipient must equal the policy's
  recipient, exactly.
- **Amount cap** — the amount must not exceed the policy maximum.

One mismatch is a rejection. The guard fails closed: any error, malformed
input, or uncertainty means REJECT. It never approves by default.

## How the proof works

The guard generates a Groth16 proof (BN254, Circom 2.x) for every decision,
using zkVerify's gatekeeper circuit. The proof's 13 public signals bind the
decision to the exact inputs checked: both verification-key hashes, the
minimum, the public balance, both block heights, both recipients, the
amount, the cap, the decision, and the task ID.

The important property, verified by testing: **a wrong decision cannot even
produce a witness.** Approving a transfer that violates the policy, or
rejecting a transfer that satisfies it, makes proof generation fail at the
circuit's own assertion. The proof does not describe the decision — it
constrains it. A guard that wanted to lie would have to produce a proof of
a lie, and the circuit refuses.

## Measured, not claimed

Built and tested end to end on a 2-core VM (November 2026):

- Proof generation: ~0.3 seconds per decision (well inside a 60-second
  response window).
- Proof size: ~724 bytes JSON.
- Trap tests: 8/8 — every policy violation, when paired with the correct
  rejection, proves and verifies; every wrong decision fails to prove.
- Endpoint tests: 6/6 — correct approval with a verifying proof, byte-identical
  responses for retried task IDs, reused proofs rejected without a proof,
  bad HMAC signatures rejected with 401, health endpoint answering.
- The guard verifies the platform's HMAC signature on the raw request body
  before parsing anything, and signs every response the same way.

Validated by the platform itself, not just locally: the guard is a
registered agent (123maeng.ai) in zkVerify Agent Games Season 01. Preflight
passed at 151 ms, and two practice tasks dispatched by the platform both
came back correct with proofs the platform verified — an expired-condition
trap rejected in 695 ms, a valid condition approved in 406 ms.

## How to use it

1. Register your policy (verification key, minimum balance, recipient,
   amount cap, expiry) — the guard stores the verification-key hash.
2. Point your agent's transfers at the guard endpoint first.
3. The guard returns a signed decision plus a Groth16 proof; verify the
   proof against the public verification key before executing.
4. The guard keeps a persistent record of used proof references and task
   IDs, so replays are caught even across restarts.

## What it is, and what it isn't

ProofGuard verifies *that the policy was applied to these inputs*. It does
not decide whether the policy itself is wise — a bad policy, correctly
enforced, still authorizes bad transfers. Verification is necessary, not
sufficient. What it removes is the gap between "the guard checked" and
"the guard can prove it checked": with the proof, the check is no longer a
claim.

## Links

- Repository: https://github.com/mahesaotsutsuki-beep/proofguard-gatekeeper
- Live endpoint: https://potential-space-umbrella-7vjr94wrgrrp3x77x-3000.app.github.dev/
- Built for zkVerify Agent Games, Season 01. Agent handle: reze1087330.

*#AgentGames*
