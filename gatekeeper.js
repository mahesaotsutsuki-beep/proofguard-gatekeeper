// reze1087330 Gatekeeper agent for zkVerify Agent Games (Proof Gatekeeper).
// Node.js, no framework. Receives a signed task envelope, decides
// deterministically against the 7 trap types, proves the decision with the
// tournament's own Groth16 circuit (snarkjs), returns a signed response.
//
// MUST-CONFIRM after registration (practice mode):
//   - HMAC header format (assumed hex HMAC-SHA256 in x-agent-games-signature)
//   - preflight shape adopted from the official /build starter prompt
//     ({ ok: true, protocolVersion: "v1" }) — confirm against a real preflight.
//   - taskId encoding as a public signal (sha256-of-string, numeric passthrough).
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || process.env.AGENT_HMAC_SECRET || "";
const STATE_FILE = (process.env.VERCEL || process.env.VERCEL_ENV || process.env.VERCEL_URL || process.env.AWS_LAMBDA_FUNCTION_NAME || __dirname.startsWith("/var/task")) ? "/tmp/agentgames-state.json" : path.join(__dirname, "state.json");
// Circuit artifacts live in circuits/ next to this file in the deployed repo,
// or one level up in the dev layout (agent/../circuits). Prefer the local one.
function circuitPath(name) {
  const local = path.join(__dirname, "circuits", name);
  if (fs.existsSync(local)) return local;
  return path.join(__dirname, "..", "circuits", name);
}
const WASM = circuitPath("gatekeeper.wasm");
const ZKEY = circuitPath("gatekeeper_final.zkey");

if (!HMAC_SECRET) console.warn("[warn] HMAC secret unset (AGENT_GAMES_HMAC_SECRET) - using dev secret, DO NOT use live");
const SECRET = HMAC_SECRET || "dev-secret-do-not-use-live";

// ---- persistent state: seen proof refs + task response cache ----
let state = { seenProofs: {}, taskCache: {} };
try {
  state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
} catch { /* first run */ }
function saveState() {
  try {
    fs.writeFileSync(STATE_FILE + ".tmp", JSON.stringify(state));
    fs.renameSync(STATE_FILE + ".tmp", STATE_FILE);
  } catch { /* stateless host: keep in-memory state only */ }
}

let vk = null;
async function getVk() {
  if (!vk) vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
  return vk;
}

function hexToDec(hex) {
  return BigInt(hex).toString();
}
function hmacHex(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}
function verifyHmac(body, sig) {
  if (!sig) return false;
  const clean = sig.startsWith("sha256=") ? sig.slice(7) : sig;
  const expected = Buffer.from(hmacHex(body), "utf8");
  const actual = Buffer.from(clean, "utf8");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

// ---- deterministic decision (trap encyclopedia order) ----
function decide(input) {
  const {
    registered_vk, proof_vk, minimum, public_balance,
    expiry_block, current_block, recipient, condition_recipient,
    amount, max_transfer, proof_tx,
  } = input;
  const norm = (a) => String(a || "").toLowerCase();
  if (norm(proof_vk) !== norm(registered_vk))
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  if (BigInt(public_balance) < BigInt(minimum))
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  if (proof_tx && state.seenProofs[proof_tx])
    return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  if (BigInt(current_block) >= BigInt(expiry_block))
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  if (norm(recipient) !== norm(condition_recipient))
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  if (BigInt(amount) > BigInt(max_transfer))
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

async function proveDecision(input, decision) {
  const circuitInput = {
    registeredVkHash: hexToDec(input.registered_vk),
    proofVkHash: hexToDec(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: hexToDec(input.recipient),
    conditionRecipient: hexToDec(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: String(input.task_id_hash || "0"),
    salt: BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  const v = await getVk();
  const ok = await snarkjs.groth16.verify(v, publicSignals, proof);
  if (!ok) throw new Error("local proof self-check failed");
  return { proof, public_signals: publicSignals };
}

function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "x-agent-games-signature": hmacHex(body),
  });
  res.end(body);
}

function handleRequest(req, res) {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    try {
      const raw = Buffer.concat(chunks);
      if (req.method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", agent: "reze1087330-gatekeeper" }));
        return;
      }
      if (req.method !== "POST") {
        res.writeHead(405); res.end(); return;
      }
      // 1. HMAC first, before parsing.
      if (!verifyHmac(raw, req.headers["x-agent-games-signature"])) {
        res.writeHead(401); res.end(JSON.stringify({ error: "bad signature" })); return;
      }
      let env;
      try {
        env = JSON.parse(raw.toString("utf8"));
      } catch {
        res.writeHead(400); res.end(JSON.stringify({ error: "bad json" })); return;
      }
      // Preflight handshake: shape from the official /build starter prompt
      // ({ ok: true, protocolVersion: "v1" }, signed). Confirm in practice.
      if (env.type && String(env.type).includes("preflight")) {
        sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
        return;
      }
      const taskId = env.task_id || env.taskId || "";
      const input = env.input || env;
      // 2. Idempotency: retried task returns the identical cached response.
      if (taskId && state.taskCache[taskId]) {
        sendSigned(res, 200, state.taskCache[taskId]);
        return;
      }
      // 3. Decide.
      let result;
      try {
        result = decide({ ...input, task_id_hash: taskIdHash(taskId) });
      } catch (e) {
        // Fail closed on malformed input.
        result = { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
      }
      // Response schema exactly as the /build starter prompt specifies:
      // { decision, reason_code, proof, public_signals }. No extra fields
      // (the platform strictly validates response schemas elsewhere).
      const response = {
        decision: result.decision,
        reason_code: result.reason_code,
      };
      // 4. Prove (PROOF_REUSED tasks carry no proof by design).
      if (result.reason_code !== "PROOF_REUSED") {
        try {
          const { proof, public_signals } = await proveDecision(
            { ...input, task_id_hash: taskIdHash(taskId) },
            result.decision
          );
          response.proof = proof;
          response.public_signals = public_signals;
        } catch (e) {
          // Correct decision, unprovable locally: still return the decision
          // (+10 beats a wrong REJECT at -3). Log loudly.
          console.error("[prove-failed]", taskId, e.message);
        }
      }
      // 5. Remember proof ref + cache response.
      if (input.proof_tx && result.decision === "APPROVE") state.seenProofs[input.proof_tx] = 1;
      if (taskId) state.taskCache[taskId] = response;
      saveState();
      sendSigned(res, 200, response);
    } catch (e) {
      console.error("[fatal]", e.message);
      res.writeHead(500); res.end(JSON.stringify({ error: "internal" }));
    }
  });
}

const server = http.createServer(handleRequest);

// taskId is a string like "gk_24_9d1"; the circuit takes a field element.
// Encoding is private-input-only unless the platform checks it as public -
// keccak-style hash keeps it deterministic. MUST-CONFIRM if public.
function taskIdHash(taskId) {
  if (!taskId) return "0";
  if (/^[0-9]+$/.test(taskId)) return taskId;
  return BigInt("0x" + crypto.createHash("sha256").update(taskId).digest("hex")).toString();
}

if (require.main === module) server.listen(PORT, () => console.log(`gatekeeper listening on :${PORT}`));

module.exports = { handler: handleRequest, server };
