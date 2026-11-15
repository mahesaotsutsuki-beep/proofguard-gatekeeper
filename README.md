# ProofGuard — Proof Gatekeeper agent (zkVerify Agent Games)

A wallet-guard agent that proves every approve/reject decision it makes.
Built for zkVerify's Agent Games, Proof Gatekeeper track (Season 01).
Agent handle: **reze1087330**.

## What it does

The agent exposes one HTTPS endpoint. For each signed task describing a
transfer request, it:

1. Verifies the platform's HMAC-SHA256 signature on the raw request body
   before parsing anything (401 on a bad signature).
2. Decides deterministically against a fixed checklist: verification-key
   match, balance threshold, proof freshness, expiry, recipient match,
   amount cap. One mismatch is a rejection. Any error fails closed
   (REJECT).
3. Generates a Groth16 proof of its decision with the tournament's own
   gatekeeper circuit (snarkjs, BN254), and returns the proof plus its
   13 public signals in a signed response.
4. Persists every proof reference and task ID, so replays are caught and
   retried tasks return the byte-identical cached response.

A wrong decision cannot even produce a witness: the circuit refuses to
prove an approval of a policy violation or a rejection of a valid request.

## Quickstart

```bash
npm install
AGENT_HMAC_SECRET=<secret from agent registration> node server.cjs
```

`GET /` returns a health JSON. `POST /` takes a signed task envelope and
returns a signed decision. Port defaults to 3000 (`PORT` env var).

## Tests (measured on a 2-core VM, Nov 2026)

```bash
node trap-test.cjs   # 8/8: wrong decisions fail to prove, correct ones verify
node e2e-test.cjs    # 6/6: approve+proof, replay, reuse, trap, bad HMAC, health
node probe.cjs       # circuit probe: ~0.3s per proof, 724-byte proof JSON
```

## Circuits

`circuits/gatekeeper.wasm` and `circuits/gatekeeper_final.zkey` are the
official tournament circuit files, downloaded from agentgames.zkverify.io.
Registered verification-key hash:
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.

## Open items

- The task-ID encoding (a public signal) and the exact proof field names
  in the response are confirmed against practice mode after registration.
- The public endpoint URL is set at deployment (ngrok/VPS).

## License

All rights reserved for now — license TBD by the owner.
