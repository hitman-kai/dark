#!/usr/bin/env node
/**
 * DarkDrop V4 — #16 constructed-localnet repro: claim against an
 * orphaned-after-sentinel root on a migrated+wrapped tree SUCCEEDS.
 *
 * A fresh new-program tree is 256 slots and never produces the orphan
 * pattern — it only arises when a WRAPPED 30-slot V1 ring is migrated to
 * 256 (slots 0..30 all live, root_history_index mid-ring, 30..256 sentinel).
 * So we reconstruct that precondition: preload a crafted 30-slot tree (real
 * root R in slot 20, index=5, current_root != R), run the REAL
 * migrate_schema_v2, then claim_credit with merkle_root = R.
 *
 * Two modes (validator lifecycle is handled by the bash orchestrator, which
 * mirrors deploy-test.sh — the proven pattern in this environment):
 *   prep <dir>  — craft wallet + account fixtures + pdas.sh into <dir>
 *   run  <dir>  — connect to $RPC_URL, migrate, prove, claim, print verdict
 *
 * PASS = claim_credit SUCCEEDS (is_known_root finds R in slot 20 via the
 *        full-buffer scan; the #16 fix). On the pre-fix backward-walk this
 *        fails with InvalidRoot (R never examined).
 *
 * Keyless: uses a throwaway wallet generated in prep; never the upgrade key.
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

const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const BUILD_DIR = path.join(__dirname, "../circuits/build");
const WASM_PATH = path.join(BUILD_DIR, "darkdrop_js/darkdrop.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "darkdrop_v2_final.zkey");
const VK_PATH = path.join(BUILD_DIR, "verification_key_v2.json");
const MERKLE_DEPTH = 20;
const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const ROOT_HISTORY_SIZE = 256, ROOT_HISTORY_SIZE_V1 = 30;
const OLD_TREE_SIZE = 8 + 72 + ROOT_HISTORY_SIZE_V1 * 32 + MERKLE_DEPTH * 32; // 1680
const NEW_TREE_SIZE = 8 + 72 + ROOT_HISTORY_SIZE * 32 + MERKLE_DEPTH * 32;    // 8912
const ORPHAN_SLOT = 20, RHI = 5;

let poseidon, F;
const ph = (a) => F.toObject(poseidon(a));
function b2bi(b){ let h=""; for (const x of b) h+=x.toString(16).padStart(2,"0"); return BigInt("0x"+(h||"0")); }
function bi2b(v){ const h=BigInt(v).toString(16).padStart(64,"0"); const b=Buffer.alloc(32); for(let i=0;i<32;i++) b[i]=parseInt(h.substr(i*2,2),16); return b; }
const pkField = (pk) => ph([b2bi(pk.slice(0,16)), b2bi(pk.slice(16,32))]);
const disc = (n) => crypto.createHash("sha256").update(`global:${n}`).digest().slice(0,8);
const accDisc = (n) => crypto.createHash("sha256").update(`account:${n}`).digest().slice(0,8);
const zeros = () => { const z=[0n]; for(let i=0;i<MERKLE_DEPTH;i++) z.push(ph([z[i],z[i]])); return z; };

function pdas() {
  const [vault, vaultBump] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
  const [merkleTree] = PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID);
  const [notePoolTree] = PublicKey.findProgramAddressSync([Buffer.from("note_pool_tree"), vault.toBytes()], PROGRAM_ID);
  return { vault, vaultBump, merkleTree, notePoolTree };
}
function writeAccountFile(file, pubkey, dataBuf, lamports) {
  fs.writeFileSync(file, JSON.stringify({
    pubkey: pubkey.toBase58(),
    account: { lamports, data: [dataBuf.toString("base64"), "base64"], owner: PROGRAM_ID.toBase58(), executable: false, rentEpoch: 0, space: dataBuf.length },
  }));
}

// Deterministic-from-secrets reconstruction of the leaf, root R, and inclusion path (index 0).
function deriveLeaf(secrets, Z) {
  const secret = BigInt(secrets.secret), nullifier = BigInt(secrets.nullifier), blinding = BigInt(secrets.blinding);
  const dropAmount = BigInt(secrets.dropAmount);
  const leaf = ph([secret, nullifier, dropAmount, blinding]);
  const amtCommitment = ph([dropAmount, blinding]);
  const nullHash = ph([nullifier]);
  let cur = leaf; for (let i = 0; i < MERKLE_DEPTH; i++) cur = ph([cur, Z[i]]);  // index 0
  return { secret, nullifier, blinding, dropAmount, leaf, amtCommitment, nullHash, R: cur };
}

async function prep(dir) {
  poseidon = await buildPoseidon(); F = poseidon.F;
  const Z = zeros(); const SENTINEL = bi2b(Z[MERKLE_DEPTH]);
  const { vault, vaultBump, merkleTree, notePoolTree } = pdas();

  const wallet = Keypair.generate();
  const recipient = Keypair.generate();
  const secrets = {
    secret: ("0x" + crypto.randomBytes(31).toString("hex")),
    nullifier: ("0x" + crypto.randomBytes(31).toString("hex")),
    blinding: ("0x" + crypto.randomBytes(31).toString("hex")),
    dropAmount: (BigInt(0.1 * LAMPORTS_PER_SOL)).toString(),
    recipientPub: recipient.publicKey.toBase58(),
  };
  // normalize to decimal strings
  secrets.secret = BigInt(secrets.secret).toString();
  secrets.nullifier = BigInt(secrets.nullifier).toString();
  secrets.blinding = BigInt(secrets.blinding).toString();

  const d = deriveLeaf(secrets, Z);
  const Rbytes = bi2b(d.R);

  // 30-slot (pre-migration, wrapped) MerkleTreeAccount: R in slot 20, index 5, current_root != R.
  const mt = Buffer.alloc(OLD_TREE_SIZE);
  accDisc("MerkleTreeAccount").copy(mt, 0);
  vault.toBuffer().copy(mt, 8);
  mt.writeUInt32LE(1, 40);              // next_index
  mt.writeUInt32LE(RHI, 44);            // root_history_index = 5
  Buffer.alloc(32, 0xAB).copy(mt, 48);  // current_root = ARB (!= R)
  for (let s = 0; s < ROOT_HISTORY_SIZE_V1; s++) {
    const off = 80 + s * 32;
    if (s === ORPHAN_SLOT) Rbytes.copy(mt, off);
    else { const b = Buffer.alloc(32); b[0] = 0xC0; b[1] = s; b.copy(mt, off); }
  }

  // vault (authority = throwaway wallet)
  const vb = Buffer.alloc(113);
  accDisc("Vault").copy(vb, 0);
  vb.writeUInt8(vaultBump, 8);
  wallet.publicKey.toBuffer().copy(vb, 9);
  vb.writeBigUInt64LE(1n, 41);
  vb.writeBigUInt64LE(0n, 49);
  vb.writeBigUInt64LE(BigInt(100 * LAMPORTS_PER_SOL), 57);
  merkleTree.toBuffer().copy(vb, 65);
  vb.writeBigUInt64LE(d.dropAmount, 97);
  vb.writeBigUInt64LE(0n, 105);

  // note-pool tree at NEW size so migrate skips it
  const np = Buffer.alloc(NEW_TREE_SIZE);
  accDisc("NotePoolTree").copy(np, 0);
  vault.toBuffer().copy(np, 8);
  SENTINEL.copy(np, 48);
  for (let s = 0; s < ROOT_HISTORY_SIZE; s++) SENTINEL.copy(np, 80 + s * 32);

  writeAccountFile(path.join(dir, "vault.json"), vault, vb, LAMPORTS_PER_SOL);
  writeAccountFile(path.join(dir, "mt.json"), merkleTree, mt, LAMPORTS_PER_SOL);
  writeAccountFile(path.join(dir, "np.json"), notePoolTree, np, LAMPORTS_PER_SOL);
  fs.writeFileSync(path.join(dir, "wallet.json"), JSON.stringify(Array.from(wallet.secretKey)));
  fs.writeFileSync(path.join(dir, "secrets.json"), JSON.stringify(secrets));
  fs.writeFileSync(path.join(dir, "pdas.sh"),
    `VAULT_PDA=${vault.toBase58()}\nMT_PDA=${merkleTree.toBase58()}\nNP_PDA=${notePoolTree.toBase58()}\nWALLET_PUB=${wallet.publicKey.toBase58()}\n`);
  console.log("prep: fixtures written to", dir);
  console.log("prep: R (orphan-slot root) =", Rbytes.toString("hex"));
}

async function run(dir) {
  poseidon = await buildPoseidon(); F = poseidon.F;
  const Z = zeros(); const SENTINEL = bi2b(Z[MERKLE_DEPTH]);
  const { vault, merkleTree, notePoolTree } = pdas();
  const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8898";

  const wallet = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(path.join(dir, "wallet.json")))));
  const secrets = JSON.parse(fs.readFileSync(path.join(dir, "secrets.json")));
  const recipient = new PublicKey(secrets.recipientPub);
  const d = deriveLeaf(secrets, Z);
  const Rbytes = bi2b(d.R);

  const connection = new Connection(RPC_URL, { commitment: "confirmed", confirmTransactionInitialTimeout: 120000 });
  await connection.confirmTransaction(await connection.requestAirdrop(wallet.publicKey, 50 * LAMPORTS_PER_SOL));
  await connection.confirmTransaction(await connection.requestAirdrop(recipient, LAMPORTS_PER_SOL / 100));

  const preLen = (await connection.getAccountInfo(merkleTree)).data.length;
  console.log(`  preloaded merkle_tree size: ${preLen} (expected OLD ${OLD_TREE_SIZE})`);
  if (preLen !== OLD_TREE_SIZE) { console.error("FATAL: preload size mismatch"); process.exit(1); }

  // --- REAL migrate_schema_v2 ---
  console.log("\n[migrate] running migrate_schema_v2 (30->256, preserves slots 0..29, seeds sentinels)…");
  const msig = await sendAndConfirmTransaction(connection, new Transaction().add(new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: false },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: notePoolTree, isSigner: false, isWritable: true },
      { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: disc("migrate_schema_v2"),
  })), [wallet]);
  console.log(`  migrate TX: ${msig}`);

  const postInfo = await connection.getAccountInfo(merkleTree);
  const slot20 = postInfo.data.slice(80 + ORPHAN_SLOT * 32, 80 + ORPHAN_SLOT * 32 + 32);
  const slot255 = postInfo.data.slice(80 + 255 * 32, 80 + 255 * 32 + 32);
  console.log(`  post-migrate size: ${postInfo.data.length} (expected NEW ${NEW_TREE_SIZE})`);
  console.log(`  slot ${ORPHAN_SLOT} preserved == R: ${slot20.equals(Rbytes)}`);
  console.log(`  slot 255 == sentinel: ${slot255.equals(SENTINEL)}  -> R is orphaned-after-sentinel for the backward walk`);
  if (postInfo.data.length !== NEW_TREE_SIZE || !slot20.equals(Rbytes) || !slot255.equals(SENTINEL)) { console.error("FATAL: post-migration layout unexpected"); process.exit(1); }

  // --- real V2 proof for leaf L against R (index 0) ---
  console.log("\n[proof] generating V2 proof for leaf L with merkle_root = R…");
  const pathElements = Z.slice(0, MERKLE_DEPTH).map(z => z.toString());
  const pathIndices = Array(MERKLE_DEPTH).fill("0");
  const recipientField = pkField(recipient.toBytes());
  const { proof, publicSignals } = await snarkjs.groth16.fullProve({
    secret: d.secret.toString(), amount: d.dropAmount.toString(), blinding_factor: d.blinding.toString(),
    nullifier: d.nullifier.toString(), merkle_path: pathElements, merkle_indices: pathIndices,
    password: "0", merkle_root: d.R.toString(), nullifier_hash: d.nullHash.toString(),
    recipient: recipientField.toString(), amount_commitment: d.amtCommitment.toString(), password_hash: "0",
  }, WASM_PATH, ZKEY_PATH);
  if (!(await snarkjs.groth16.verify(JSON.parse(fs.readFileSync(VK_PATH)), publicSignals, proof))) { console.error("  local proof verify FAILED"); process.exit(1); }
  console.log("  proof OK; publicSignals[0] == R:", BigInt(publicSignals[0]) === d.R);

  const proofA = Buffer.concat([bi2b(proof.pi_a[0]), bi2b(BN254_FQ - BigInt(proof.pi_a[1]))]);
  const proofB = Buffer.concat([bi2b(proof.pi_b[0][1]), bi2b(proof.pi_b[0][0]), bi2b(proof.pi_b[1][1]), bi2b(proof.pi_b[1][0])]);
  const proofC = Buffer.concat([bi2b(proof.pi_c[0]), bi2b(proof.pi_c[1])]);
  const opaqueInputs = Buffer.concat([Rbytes, bi2b(d.amtCommitment), bi2b(0n)]);
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(opaqueInputs.length);
  const nBytes = bi2b(d.nullHash);
  const [nullifierPDA] = PublicKey.findProgramAddressSync([Buffer.from("nullifier"), nBytes], PROGRAM_ID);
  const [creditPDA] = PublicKey.findProgramAddressSync([Buffer.from("credit"), nBytes], PROGRAM_ID);
  const claimData = Buffer.concat([disc("claim_credit"), nBytes, proofA, proofB, proofC, Buffer.concat([lenBuf, opaqueInputs]), bi2b("0x" + crypto.randomBytes(31).toString("hex"))]);

  console.log("\n[claim] claim_credit with merkle_root = R (orphaned slot 20)…");
  try {
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vault, isSigner: false, isWritable: true },
          { pubkey: merkleTree, isSigner: false, isWritable: false },
          { pubkey: creditPDA, isSigner: false, isWritable: true },
          { pubkey: nullifierPDA, isSigner: false, isWritable: true },
          { pubkey: recipient, isSigner: false, isWritable: false },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: claimData,
      }),
    ), [wallet]);
    console.log(`  claim_credit TX: ${sig}`);
    const created = (await connection.getAccountInfo(creditPDA)) !== null;
    console.log(`  credit note created: ${created}`);
    if (created) { console.log("\n=== PASS: claim against orphaned-after-sentinel root R SUCCEEDED (is_known_root full-scan found it) ==="); process.exit(0); }
    console.log("\n=== FAIL: claim TX landed but no credit note created ==="); process.exit(1);
  } catch (e) {
    console.error("  claim_credit FAILED:", e.message);
    (e.logs||[]).forEach(l=>console.error("   ",l));
    const hay = ((e.message||"") + (e.logs||[]).join("\n")).toLowerCase();
    if (hay.includes("invalidroot") || hay.includes("6001")) console.log("\n=== FAIL: InvalidRoot — orphaned root NOT found (pre-fix bug; fix missing from .so?) ===");
    else console.log("\n=== FAIL: claim errored for another reason — investigate above ===");
    process.exit(1);
  }
}

const mode = process.argv[2], dir = process.argv[3];
if (!["prep","run"].includes(mode) || !dir) { console.error("usage: assert-orphan-root-claim.js <prep|run> <dir>"); process.exit(2); }
(mode === "prep" ? prep(dir) : run(dir)).catch(e => { console.error("Fatal:", e); process.exit(1); });
