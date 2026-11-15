// Trap tests: the circuit must REFUSE wrong decisions (witness build fails)
// and ACCEPT correct ones. Validates the decision<->proof binding.
const snarkjs = require("snarkjs");
const path = require("path");

const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIP = "0xDe42a1b0c2345678901234567890123456789f01";
const OTHER = "0x1111111111111111111111111111111111111111";
const dec = (h) => BigInt(h).toString();

function base(over = {}) {
  return {
    registeredVkHash: dec(VK_HASH),
    proofVkHash: dec(VK_HASH),
    minimum: "1000",
    publicBalance: "1460",
    expiryBlock: "19842201",
    currentBlock: "19832000",
    recipient: dec(RECIP),
    conditionRecipient: dec(RECIP),
    amount: "500",
    maxTransfer: "1000",
    decision: "1",
    taskId: "777",
    salt: "424242",
    ...over,
  };
}

async function tryProve(name, input, wantOk) {
  try {
    const t0 = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(`${name}: proved in ${Date.now() - t0}ms, verify=${ok} (want prove=${wantOk}) ${ok === wantOk ? "PASS" : "FAIL"}`);
  } catch (e) {
    console.log(`${name}: fullProve threw (${e.message.slice(0, 80)}) (want prove=${wantOk}) ${!wantOk ? "PASS" : "FAIL"}`);
  }
}

(async () => {
  await tryProve("valid + approve", base(), true);
  await tryProve("valid + reject (wrong)", base({ decision: "0" }), false);
  await tryProve("recipient trap + approve (wrong)", base({ recipient: dec(OTHER) }), false);
  await tryProve("recipient trap + reject", base({ recipient: dec(OTHER), decision: "0" }), true);
  await tryProve("threshold trap + reject", base({ publicBalance: "999", decision: "0" }), true);
  await tryProve("expired + reject", base({ currentBlock: "19842201", decision: "0" }), true);
  await tryProve("amount overflow + reject", base({ amount: "1001", decision: "0" }), true);
  await tryProve("vk substitution + reject", base({ proofVkHash: dec("0x" + "ab".repeat(32)), decision: "0" }), true);
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
