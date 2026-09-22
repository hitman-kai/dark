#!/usr/bin/env node
/**
 * DarkDrop V4 — #17 assertion: non-canonical nullifier (n + r) is rejected,
 * canonical (n) still succeeds.
 *
 * Flow (mirrors e2e-credit-test.js for the canonical leg):
 *   1. init vault (idempotent) + create_drop
 *   2. generate a real V2 proof for the leaf
 *   3. canonical claim_credit with nullifier_hash = n  → MUST SUCCEED
 *   4. malleable claim_credit with nullifier_hash = n + r (BN254 scalar order),
 *      SAME proof + SAME opaque inputs → MUST FAIL with NonCanonicalInput (6025)
 *
 * The malleable twin n+r is byte-distinct from n (distinct PDAs) yet maps to
 * the same scalar in the proof — the #17 double-spend surface. The fix's
 * require_canonical_inputs guard rejects it before the verifier / PDA init.
 *
 * Env: RPC_URL, PROGRAM_ID, KEYPAIR.
 */
const {
  Connection, Keypair, PublicKey, Transaction, TransactionInstruction,
  SystemProgram, ComputeBudgetProgram, sendAndConfirmTransaction, LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const BUILD_DIR = path.join(__dirname, "../circuits/build");
const WASM_PATH = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "darkdrop_v2_final.zkey");
const VK_PATH = path.join(BUILD_DIR, "verification_key_v2.json");
const MERKLE_DEPTH = 20;
const DROP_CAP = BigInt(100 * LAMPORTS_PER_SOL);

// BN254 base field prime (for proof point y-negation).
const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
// BN254 SCALAR field order r — the malleability modulus (n and n+r share a scalar).
const BN254_R  = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let poseidon, F;
const poseidonHash = (inputs) => F.toObject(poseidon(inputs));
const randomField = () => BigInt("0x" + crypto.randomBytes(31).toString("hex"));
function bytesToBigIntBE(b) { let h=""; for (const x of b) h += x.toString(16).padStart(2,"0"); return BigInt("0x"+(h||"0")); }
function bigintToBytes32BE(v) { const h=BigInt(v).toString(16).padStart(64,"0"); const b=Buffer.alloc(32); for (let i=0;i<32;i++) b[i]=parseInt(h.substr(i*2,2),16); return b; }
const bigintToBE32 = bigintToBytes32BE;
function pubkeyToField(pk) { return poseidonHash([bytesToBigIntBE(pk.slice(0,16)), bytesToBigIntBE(pk.slice(16,32))]); }
function disc(name) { return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0,8); }
const getZeroHashes = () => { const z=[0n]; for (let i=0;i<MERKLE_DEPTH;i++) z.push(poseidonHash([z[i],z[i]])); return z; };

function buildClaimCreditData(nullifierHashBytes, proofA, proofB, proofC, opaqueInputs, saltBytes) {
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(opaqueInputs.length);
  return Buffer.concat([
    disc("claim_credit"), nullifierHashBytes, proofA, proofB, proofC,
    Buffer.concat([lenBuf, opaqueInputs]), saltBytes,
  ]);
}
function claimCreditIx(nullifierHashBytes, data, vault, merkleTree, recipient, payer) {
  const [nullifierPDA] = PublicKey.findProgramAddressSync([Buffer.from("nullifier"), nullifierHashBytes], PROGRAM_ID);
  const [creditNotePDA] = PublicKey.findProgramAddressSync([Buffer.from("credit"), nullifierHashBytes], PROGRAM_ID);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: false },
      { pubkey: creditNotePDA, isSigner: false, isWritable: true },
      { pubkey: nullifierPDA, isSigner: false, isWritable: true },
      { pubkey: recipient, isSigner: false, isWritable: false },
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

async function main() {
  console.log("=== DarkDrop V4 — #17: assert non-canonical (n+r) rejected, canonical (n) succeeds ===\n");
  poseidon = await buildPoseidon(); F = poseidon.F;

  const connection = new Connection(RPC_URL, { commitment: "confirmed", confirmTransactionInitialTimeout: 120000 });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const recipient = Keypair.generate();

  const [vault] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
  const [merkleTree] = PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID);
  const [treasury] = PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID);

  // STEP 1: init vault (idempotent) + create_drop
  const dropCapBuf = Buffer.alloc(8); dropCapBuf.writeBigUInt64LE(DROP_CAP);
  try {
    await sendAndConfirmTransaction(connection, new Transaction().add(new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: true },
        { pubkey: treasury, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([disc("initialize_vault"), dropCapBuf]),
    })), [payer]);
    console.log("  vault initialized");
  } catch (e) {
    if ((e.message||"").includes("already in use")) console.log("  vault already initialized (skip)");
    else { console.error("  init failed:", e.message); (e.logs||[]).forEach(l=>console.error("   ",l)); process.exit(1); }
  }

  const dropAmount = BigInt(0.1 * LAMPORTS_PER_SOL);
  const secret = randomField(), nullifier = randomField(), blinding = randomField();
  const leaf = poseidonHash([secret, nullifier, dropAmount, blinding]);
  const amtCommitment = poseidonHash([dropAmount, blinding]);
  const pwdHash = 0n;
  const nullHash = poseidonHash([nullifier]);            // n (canonical, < r)

  const amountBuf = Buffer.alloc(8); amountBuf.writeBigUInt64LE(dropAmount);
  await sendAndConfirmTransaction(connection, new Transaction().add(new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([disc("create_drop"), bigintToBytes32BE(leaf), amountBuf]),
  })), [payer]);
  console.log("  drop created");

  // STEP 2: merkle proof + V2 proof
  const treeData = (await connection.getAccountInfo(merkleTree)).data;
  const nextIndex = treeData.readUInt32LE(8 + 32);
  const onChainRoot = treeData.slice(8+32+4+4, 8+32+4+4+32);
  const fsOff = 8+32+4+4+32 + 256*32;
  const filledSubtrees = [];
  for (let i=0;i<MERKLE_DEPTH;i++) filledSubtrees.push(treeData.slice(fsOff+i*32, fsOff+(i+1)*32));
  const leafIndex = nextIndex - 1;
  const zeroHashes = getZeroHashes();
  const pathElements=[], pathIndices=[]; let idx=leafIndex;
  for (let i=0;i<MERKLE_DEPTH;i++){ const bit=idx&1; pathIndices.push(bit.toString()); pathElements.push(bit===0?zeroHashes[i].toString():bytesToBigIntBE(filledSubtrees[i]).toString()); idx>>=1; }
  const recipientField = pubkeyToField(recipient.publicKey.toBytes());

  const { proof, publicSignals } = await snarkjs.groth16.fullProve({
    secret: secret.toString(), amount: dropAmount.toString(), blinding_factor: blinding.toString(),
    nullifier: nullifier.toString(), merkle_path: pathElements, merkle_indices: pathIndices,
    password: "0", merkle_root: bytesToBigIntBE(onChainRoot).toString(), nullifier_hash: nullHash.toString(),
    recipient: recipientField.toString(), amount_commitment: amtCommitment.toString(), password_hash: pwdHash.toString(),
  }, WASM_PATH, ZKEY_PATH);
  const vk = JSON.parse(fs.readFileSync(VK_PATH));
  if (!(await snarkjs.groth16.verify(vk, publicSignals, proof))) { console.error("  local proof verify FAILED"); process.exit(1); }
  console.log("  V2 proof generated + locally verified");

  const proofA = Buffer.concat([bigintToBE32(proof.pi_a[0]), bigintToBE32(BN254_FQ - BigInt(proof.pi_a[1]))]);
  const proofB = Buffer.concat([bigintToBE32(proof.pi_b[0][1]), bigintToBE32(proof.pi_b[0][0]), bigintToBE32(proof.pi_b[1][1]), bigintToBE32(proof.pi_b[1][0])]);
  const proofC = Buffer.concat([bigintToBE32(proof.pi_c[0]), bigintToBE32(proof.pi_c[1])]);
  const opaqueInputs = Buffer.concat([onChainRoot, bigintToBytes32BE(amtCommitment), bigintToBytes32BE(pwdHash)]);

  // STEP 3: canonical claim_credit (n) — MUST SUCCEED
  console.log("\n[canonical] claim_credit with nullifier_hash = n ...");
  const nBytes = bigintToBytes32BE(nullHash);
  const [creditN] = PublicKey.findProgramAddressSync([Buffer.from("credit"), nBytes], PROGRAM_ID);
  try {
    const data = buildClaimCreditData(nBytes, proofA, proofB, proofC, opaqueInputs, bigintToBytes32BE(randomField()));
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
      claimCreditIx(nBytes, data, vault, merkleTree, recipient.publicKey, payer.publicKey),
    ), [payer]);
    const created = (await connection.getAccountInfo(creditN)) !== null;
    console.log(`  TX: ${sig}`);
    console.log(`  credit note created: ${created}`);
    if (!created) { console.log("\n=== FAIL: canonical claim did not create a credit note ==="); process.exit(1); }
  } catch (e) {
    console.error("  canonical claim_credit FAILED:", e.message);
    (e.logs||[]).forEach(l=>console.error("   ",l));
    console.log("\n=== FAIL: canonical claim should succeed ===");
    process.exit(1);
  }

  // STEP 4: malleable claim_credit (n + r) — MUST FAIL with NonCanonicalInput
  console.log("\n[malleable] claim_credit with nullifier_hash = n + r ...");
  const nPlusR = nullHash + BN254_R;
  const nPlusRBytes = bigintToBytes32BE(nPlusR);
  console.log(`  n      = ${nullHash.toString(16)}`);
  console.log(`  n + r  = ${nPlusR.toString(16)}  (distinct 32-byte string, distinct PDAs)`);
  let mSucceeded = false, mErr = "", mLogs = [];
  try {
    const data = buildClaimCreditData(nPlusRBytes, proofA, proofB, proofC, opaqueInputs, bigintToBytes32BE(randomField()));
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
      claimCreditIx(nPlusRBytes, data, vault, merkleTree, recipient.publicKey, payer.publicKey),
    ), [payer]);
    mSucceeded = true;
    console.log(`  TX UNEXPECTEDLY SUCCEEDED: ${sig}`);
  } catch (e) { mErr = e.message||String(e); mLogs = e.logs||[]; }

  if (mSucceeded) { console.log("\n=== FAIL: n+r was accepted — double-spend surface still open ==="); process.exit(1); }
  console.log("  rejected (as expected). logs:");
  mLogs.forEach(l => console.log(`    log: ${l}`));
  const hay = (mErr + "\n" + mLogs.join("\n")).toLowerCase();
  // NonCanonicalInput is DarkDropError variant #25 → Anchor code 6000+25 = 6025 (0x1789).
  const ok = hay.includes("noncanonicalinput") || hay.includes("6025") || hay.includes("0x1789")
    || hay.includes("not a canonical");
  if (ok) {
    console.log("\n=== PASS: n+r rejected with NonCanonicalInput; canonical n succeeded ===");
    process.exit(0);
  }
  console.log(`  raw error: ${mErr}`);
  console.log("\n=== FAIL: n+r was rejected but NOT with NonCanonicalInput — investigate ===");
  process.exit(1);
}

main().catch(e => { console.error("Fatal:", e); process.exit(1); });
