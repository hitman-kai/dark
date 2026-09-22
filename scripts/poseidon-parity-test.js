#!/usr/bin/env node
/**
 * Poseidon parity vector — issue #22 / I2.
 *
 * The relayer and frontend reconstruct commitments, recipient_hash, and salt
 * off-chain with circomlibjs Poseidon, which MUST byte-match the on-chain
 * light-hasher Poseidon. If a circomlibjs version drift (e.g. from a missing
 * lockfile — see #21) silently changed the hash, the relayer would pre-verify a
 * DIFFERENT statement than the chain (a liveness/gas footgun).
 *
 * This pins that equivalence to a COMMITTED test vector: the on-chain
 * `ZERO_HASHES` constants from `program/programs/darkdrop/src/state.rs` are the
 * ground truth (baked into the deployed program). They are, by definition:
 *     ZERO_HASHES[0]   = 0^32
 *     ZERO_HASHES[i+1] = Poseidon(ZERO_HASHES[i], ZERO_HASHES[i])
 * so circomlibjs must reproduce them. Drift fails this test instead of silently
 * shipping a mismatched hasher.
 *
 * Run in relayer + frontend CI against THAT package's installed circomlibjs
 * (NODE_PATH=<pkg>/node_modules). Exit 0 = parity holds; non-zero = drift.
 */
const { buildPoseidon } = require("circomlibjs");

// Verbatim from program/programs/darkdrop/src/state.rs (big-endian 32-byte).
const ZH = {
  0: new Array(32).fill(0),
  1: [32, 152, 245, 251, 158, 35, 158, 171, 60, 234, 195, 242, 123, 129, 228, 129, 220, 49, 36, 213, 95, 254, 213, 35, 168, 57, 238, 132, 70, 182, 72, 100],
  2: [16, 105, 103, 61, 205, 177, 34, 99, 223, 48, 26, 111, 245, 132, 167, 236, 38, 26, 68, 203, 157, 198, 141, 240, 103, 164, 119, 68, 96, 177, 241, 225],
};

const bytesToBig = (b) => BigInt("0x" + b.map((x) => x.toString(16).padStart(2, "0")).join(""));
const bigToBytes = (v) => v.toString(16).padStart(64, "0").match(/../g).map((x) => parseInt(x, 16));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

(async () => {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const h = (ins) => bigToBytes(F.toObject(poseidon(ins.map(BigInt))));

  let ver = "unknown";
  try { ver = require("circomlibjs/package.json").version; } catch {}
  console.log(`=== Poseidon parity vector (circomlibjs ${ver} <-> on-chain light-hasher) ===`);

  const checks = [
    { name: "Poseidon(ZH0, ZH0) == ZERO_HASHES[1]", got: h([bytesToBig(ZH[0]), bytesToBig(ZH[0])]), want: ZH[1] },
    { name: "Poseidon(ZH1, ZH1) == ZERO_HASHES[2]", got: h([bytesToBig(ZH[1]), bytesToBig(ZH[1])]), want: ZH[2] },
  ];

  let ok = true;
  for (const c of checks) {
    const m = eq(c.got, c.want);
    ok = ok && m;
    console.log(`  [${m ? "MATCH" : "MISMATCH"}] ${c.name}`);
    if (!m) {
      console.log(`      got : ${c.got.map((x) => x.toString(16).padStart(2, "0")).join("")}`);
      console.log(`      want: ${c.want.map((x) => x.toString(16).padStart(2, "0")).join("")}`);
    }
  }

  if (ok) {
    console.log("\nPARITY OK — circomlibjs Poseidon matches the on-chain light-hasher.");
    process.exit(0);
  }
  console.error("\nPARITY DRIFT — circomlibjs does NOT match on-chain Poseidon. Do NOT relay until resolved.");
  process.exit(1);
})().catch((e) => { console.error("parity test error:", e.message); process.exit(2); });
