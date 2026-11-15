// End-to-end local test of server.cjs: HMAC, decisions, proofs, idempotency.
const { spawn } = require("child_process");
const crypto = require("crypto");
const http = require("http");

const SECRET = "dev-secret-do-not-use-live";
const PORT = 3101;
const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIP = "0xDe42a1b0c2345678901234567890123456789f01";

function post(path, body, secret = SECRET) {
  const raw = JSON.stringify(body);
  const sig = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port: PORT, path, method: "POST",
        headers: { "Content-Type": "application/json", "x-agent-games-signature": sig } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      }
    );
    req.on("error", reject);
    req.write(raw);
    req.end();
  });
}

function task(id, over = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: id,
    mode: "competition",
    input: {
      registered_vk: VK, proof_vk: VK, minimum: "1000", public_balance: "1460",
      expiry_block: 19842201, current_block: 19832000,
      recipient: RECIP, condition_recipient: RECIP,
      amount: "500", max_transfer: "1000", proof_tx: "0xaaa" + id, ...over,
    },
  };
}

(async () => {
  const srv = spawn("node", ["server.cjs"], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(PORT), AGENT_HMAC_SECRET: SECRET },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  srv.stderr.on("data", (d) => (serverLog += d));
  srv.stdout.on("data", (d) => (serverLog += d));
  await new Promise((r) => setTimeout(r, 1200));
  try {
    // 1. valid task -> APPROVE + proof
    const t0 = Date.now();
    const r1 = await post("/", task("t1"));
    const b1 = JSON.parse(r1.body);
    console.log("1 valid:", r1.status, b1.decision, b1.reason_code,
      "| proof:", !!b1.proof, "| pubsig:", b1.public_signals?.length,
      "| ms:", Date.now() - t0, "| resp-signed:", !!r1.headers["x-agent-games-signature"]);
    // verify the returned proof locally
    const snarkjs = require("snarkjs");
    const vk = await snarkjs.zKey.exportVerificationKey(__dirname + "/../circuits/gatekeeper_final.zkey");
    console.log("  returned proof verifies:", b1.proof
      ? await snarkjs.groth16.verify(vk, b1.public_signals, b1.proof)
      : "NO PROOF ATTACHED");

    // 2. retry same task -> byte-identical cached response
    const r2 = await post("/", task("t1"));
    console.log("2 replay identical:", r2.body === r1.body);

    // 3. reused proof_tx -> REJECT PROOF_REUSED, no proof
    const r3 = await post("/", task("t2", { proof_tx: "0xaaat1" }));
    const b3 = JSON.parse(r3.body);
    console.log("3 reuse:", r3.status, b3.decision, b3.reason_code, "| proof:", !!b3.proof);

    // 4. trap (recipient mismatch) -> REJECT + proof
    const r4 = await post("/", task("t3", { recipient: "0x1111111111111111111111111111111111111111" }));
    const b4 = JSON.parse(r4.body);
    console.log("4 trap:", r4.status, b4.decision, b4.reason_code, "| proof:", !!b4.proof,
      "| verifies:", b4.proof ? await snarkjs.groth16.verify(vk, b4.public_signals, b4.proof) : "n/a");

    // 5. bad HMAC -> 401
    const r5 = await post("/", task("t4"), "wrong-secret");
    console.log("5 bad hmac:", r5.status);

    // 6. GET health
    const r6 = await new Promise((resolve, reject) => {
      http.get({ host: "127.0.0.1", port: PORT, path: "/" }, (res) => {
        let d = "";
        res.on("data", (c) => (d += c));
        res.on("end", () => resolve({ status: res.statusCode, body: d }));
      }).on("error", reject);
    });
    console.log("6 GET /:", r6.status, r6.body);
  } catch (e) {
    console.log("TEST ERROR:", e.message);
    console.log("--- server log ---");
    console.log(serverLog);
  } finally {
    srv.kill("SIGKILL");
    process.exit(0);
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
