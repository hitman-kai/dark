// Stage 3: SOL end-to-end flow on devnet.
//
// Deposit 0.01 SOL via create_drop → V2 proof → claim_credit →
// withdraw_credit. Assert the recipient wallet received the SOL.
//
// Uses the SOL-side instructions (audited, unchanged by this branch).
// Validates that the deploy at 8b8JX... is functionally identical to
// what the audited code expects.

import * as fs from "fs";
import { createHash } from "crypto";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";

import {
  initPoseidon,
  poseidonHash,
  nullifierHash as computeNullifierHash,
  amountCommitment as computeAmountCommitment,
  passwordHash as computePasswordHash,
  createLeaf,
  randomFieldElement,
  bigintToBytes32BE,
} from "../../frontend/src/lib/crypto";
import {
  generateClaimProofV2,
  setV2ArtifactPaths,
} from "../../frontend/src/lib/proof";

const STATE_PATH = "/tmp/dd-devnet-state.json";
const WASM_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop.wasm";
const ZKEY_V2_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop_v2_final.zkey";

function anchorDiscriminator(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function u64LE(n: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n, 0);
  return buf;
}

function u16LE(n: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(n, 0);
  return buf;
}

function u32LE(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(n, 0);
  return buf;
}

function loadKeypair(path: string): Keypair {
  const data = JSON.parse(fs.readFileSync(path, "utf8")) as number[];
  return Keypair.fromSecretKey(new Uint8Array(data));
}

const MERKLE_DEPTH = 20;

function buildSingleLeafProof(): { pathElements: bigint[]; pathIndices: number[] } {
  // For a tree with exactly one leaf at index 0, all siblings on the
  // path are zero-subtree roots and all indices are 0.
  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];
  let zero = 0n;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    pathElements.push(zero);
    pathIndices.push(0);
    zero = poseidonHash([zero, zero]);
  }
  return { pathElements, pathIndices };
}

function rootForSingleLeaf(leaf: bigint): bigint {
  let h = leaf;
  let zero = 0n;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    h = poseidonHash([h, zero]);
    zero = poseidonHash([zero, zero]);
  }
  return h;
}

async function main() {
  const state = JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
  const PROGRAM_ID = new PublicKey(state.program_id);
  const connection = new Connection(state.rpc_url, "confirmed");
  const wallet = loadKeypair(state.wallet_path);

  const vaultPDA = new PublicKey(state.sol_paths.vault);
  const merkleTreePDA = new PublicKey(state.sol_paths.merkle_tree);
  const treasuryPDA = new PublicKey(state.sol_paths.treasury);

  console.log(`[sol-flow] program=${PROGRAM_ID.toBase58()} wallet=${wallet.publicKey.toBase58()}`);

  // Fresh recipient keypair — we want to verify its balance ends at exactly the
  // deposit amount (modulo no-fee), so use a never-used pubkey.
  const recipient = Keypair.generate();
  console.log(`[sol-flow] recipient=${recipient.publicKey.toBase58()}`);

  setV2ArtifactPaths(WASM_PATH, ZKEY_V2_PATH);
  await initPoseidon();

  // === Generate deposit secrets ===
  const secret = randomFieldElement();
  const nullifier = randomFieldElement();
  const blinding = randomFieldElement();
  const password = 0n;
  const amount = BigInt(0.01 * LAMPORTS_PER_SOL); // 10,000,000 lamports

  const leaf = createLeaf(secret, nullifier, amount, blinding);
  const amtCommit = computeAmountCommitment(amount, blinding);
  const nullHash = computeNullifierHash(nullifier);
  const pwdHash = computePasswordHash(password);

  // === create_drop ===
  const leafBuf = Buffer.from(bigintToBytes32BE(leaf));
  const amtCommitBuf = Buffer.from(bigintToBytes32BE(amtCommit));
  const pwdHashBuf = Buffer.from(bigintToBytes32BE(pwdHash));

  const createDropData = Buffer.concat([
    anchorDiscriminator("create_drop"),
    leafBuf,
    u64LE(amount),
    amtCommitBuf,
    pwdHashBuf,
  ]);

  const treasuryBalBefore = await connection.getBalance(treasuryPDA, "confirmed");
  const recipientBalBefore = await connection.getBalance(recipient.publicKey, "confirmed");

  const createSig = await sendAndConfirmTransaction(connection, new Transaction().add(
    new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: merkleTreePDA, isSigner: false, isWritable: true },
        { pubkey: treasuryPDA, isSigner: false, isWritable: true },
        { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: createDropData,
    })
  ), [wallet], { commitment: "confirmed" });
  console.log(`[sol-flow] create_drop tx: ${createSig}`);

  const treasuryBalAfterDeposit = await connection.getBalance(treasuryPDA, "confirmed");
  console.log(`[sol-flow] treasury delta on deposit: +${treasuryBalAfterDeposit - treasuryBalBefore} lamports`);

  // === Build merkle proof + V2 proof ===
  const root = rootForSingleLeaf(leaf);
  const { pathElements, pathIndices } = buildSingleLeafProof();
  const merkleProof = { pathElements, pathIndices, root };

  const salt = randomFieldElement();
  const proof = await generateClaimProofV2(
    { secret, nullifier, amount, blindingFactor: blinding, password },
    merkleProof,
    recipient.publicKey,
    nullHash,
    amtCommit,
    pwdHash
  );

  // === claim_credit ===
  const nullifierHashBuf = Buffer.from(proof.nullifierHash);
  const [creditNotePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("credit"), nullifierHashBuf], PROGRAM_ID
  );
  const [nullifierPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier"), nullifierHashBuf], PROGRAM_ID
  );

  const inputs = Buffer.concat([
    Buffer.from(proof.merkleRoot),
    Buffer.from(proof.amountCommitment),
    Buffer.from(proof.passwordHash),
  ]);
  const saltBuf = Buffer.from(bigintToBytes32BE(salt));
  const claimData = Buffer.concat([
    anchorDiscriminator("claim_credit"),
    nullifierHashBuf,
    Buffer.from(proof.proofA),
    Buffer.from(proof.proofB),
    Buffer.from(proof.proofC),
    u32LE(inputs.length),
    inputs,
    saltBuf,
  ]);

  const claimSig = await sendAndConfirmTransaction(connection, new Transaction().add(
    new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: merkleTreePDA, isSigner: false, isWritable: false },
        { pubkey: creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: nullifierPDA, isSigner: false, isWritable: true },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
        { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: claimData,
    })
  ), [wallet], { commitment: "confirmed" });
  console.log(`[sol-flow] claim_credit tx: ${claimSig}`);

  // === withdraw_credit ===
  // Opening = amount(u64 LE, 8) || blinding(32 BE) || salt(32 BE)
  const opening = Buffer.concat([
    u64LE(amount),
    Buffer.from(bigintToBytes32BE(blinding)),
    saltBuf,
  ]);
  const withdrawData = Buffer.concat([
    anchorDiscriminator("withdraw_credit"),
    nullifierHashBuf,
    u32LE(opening.length),
    opening,
    u16LE(0), // rate = 0 (no fee)
  ]);

  const withdrawSig = await sendAndConfirmTransaction(connection, new Transaction().add(
    new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: treasuryPDA, isSigner: false, isWritable: true },
        { pubkey: creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
        { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: withdrawData,
    })
  ), [wallet], { commitment: "confirmed" });
  console.log(`[sol-flow] withdraw_credit tx: ${withdrawSig}`);

  // === Assertions ===
  const recipientBalAfter = await connection.getBalance(recipient.publicKey, "confirmed");
  const recipientDelta = recipientBalAfter - recipientBalBefore;
  const treasuryBalAfterWithdraw = await connection.getBalance(treasuryPDA, "confirmed");

  console.log(`[sol-flow] recipient balance: ${recipientBalBefore} → ${recipientBalAfter} (Δ ${recipientDelta})`);
  console.log(`[sol-flow] treasury balance: ${treasuryBalAfterDeposit} → ${treasuryBalAfterWithdraw}`);

  const passDelta = recipientDelta === Number(amount);
  const passTreasury = treasuryBalAfterDeposit - treasuryBalAfterWithdraw === Number(amount);

  console.log(`[sol-flow] assert recipient got ${amount} lamports: ${passDelta ? "PASS" : "FAIL"}`);
  console.log(`[sol-flow] assert treasury decreased by ${amount}: ${passTreasury ? "PASS" : "FAIL"}`);

  // Persist signatures back to state for the report.
  const stateNow = JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
  stateNow.sol_flow = {
    recipient: recipient.publicKey.toBase58(),
    amount: amount.toString(),
    create_drop: createSig,
    claim_credit: claimSig,
    withdraw_credit: withdrawSig,
    recipient_delta_lamports: recipientDelta,
    pass: passDelta && passTreasury,
  };
  fs.writeFileSync(STATE_PATH, JSON.stringify(stateNow, null, 2));

  if (!passDelta || !passTreasury) {
    console.error("[sol-flow] ASSERTIONS FAILED");
    process.exit(1);
  }
  console.log("[sol-flow] DONE");
}

main().catch((e) => {
  console.error("[sol-flow] FAILED:", e);
  process.exit(1);
});
