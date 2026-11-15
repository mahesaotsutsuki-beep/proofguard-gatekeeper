// Probe the official Gatekeeper circuit: export vk, run fullProve on a valid
// scenario, verify locally. Signal names per the public djarot write-up -
// verified empirically here (a wrong name makes fullProve throw).
const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");

const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0xDe42a1b0c2345678901234567890123456789f01";

function hexToDec(hex) {
  return BigInt(hex).toString();
}

async function main() {
  const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
  console.log("vk curve:", vk.curve, "| protocol:", vk.protocol);
  console.log("nPublic (IC-1):", vk.IC.length - 1);
  console.log("vkHash from /api/circuit-info:", VK_HASH);
  fs.writeFileSync(path.join(__dirname, "verification_key.json"), JSON.stringify(vk, null, 2));

  // Valid scenario from the official sample task payload.
  const input = {
    registeredVkHash: hexToDec(VK_HASH),
    proofVkHash: hexToDec(VK_HASH),
    minimum: "1000",
    publicBalance: "1460",
    expiryBlock: "19842201",
    currentBlock: "19832000",
    recipient: hexToDec(RECIPIENT),
    conditionRecipient: hexToDec(RECIPIENT),
    amount: "500",
    maxTransfer: "1000",
    decision: "1",
    taskId: "12345",
    salt: "987654321",
  };
  console.log("proving valid scenario...");
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  console.log("prove ms:", Date.now() - t0, "| proof bytes:", JSON.stringify(proof).length);
  console.log("publicSignals:", publicSignals);
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log("verify:", ok ? "OK" : "FAIL");
}

main().catch((e) => {
  console.error("PROBE FAILED:", e.message);
  process.exit(1);
});
