#!/usr/bin/env node
/**
 * DarkDrop V4 — #18 assertion: the legacy V1 `claim` instruction is GONE.
 *
 * Builds a transaction carrying the V1 `claim` instruction (its Anchor
 * discriminator = sha256("global:claim")[..8] plus the old V1 arg layout)
 * and submits it. Since `claim` was retired in #18, the program's Anchor
 * dispatcher no longer has a handler for that discriminator and rejects the
 * instruction (InstructionFallbackNotFound, error 0x65 / 101) BEFORE any
 * account or proof logic runs.
 *
 * PASS  = the TX fails with an unknown-instruction / fallback error.
 * FAIL  = the TX succeeds (V1 still live) or fails for an unrelated reason
 *         that suggests the handler still exists (e.g. account/proof errors).
 *
 * Env: RPC_URL, PROGRAM_ID, KEYPAIR  (same as the other e2e scripts).
 * Read-only of keys: uses whatever throwaway KEYPAIR the harness provides.
 */
const {
  Connection, Keypair, PublicKey, Transaction, TransactionInstruction,
  SystemProgram, sendAndConfirmTransaction,
} = require("@solana/web3.js");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const KEYPAIR_PATH = process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");

function disc(name) {
  return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

async function main() {
  console.log("=== DarkDrop V4 — #18: assert legacy V1 `claim` is gone ===\n");

  const connection = new Connection(RPC_URL, { commitment: "confirmed", confirmTransactionInitialTimeout: 120000 });
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(KEYPAIR_PATH))));
  const recipient = Keypair.generate();

  const [vault] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
  const [merkleTree] = PublicKey.findProgramAddressSync([Buffer.from("merkle_tree"), vault.toBytes()], PROGRAM_ID);
  const [treasury] = PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID);

  // V1 claim arg layout (from the retired claim.rs):
  //   proof: ProofData { a:64, b:128, c:64 } = 256
  //   merkle_root:32, nullifier_hash:32, amount:8,
  //   amount_commitment:32, password_hash:32, fee_lamports:8
  const nullifierHash = crypto.randomBytes(32);          // arbitrary
  const [nullifierPDA] = PublicKey.findProgramAddressSync([Buffer.from("nullifier"), nullifierHash], PROGRAM_ID);

  const amountBuf = Buffer.alloc(8);  amountBuf.writeBigUInt64LE(1n);
  const feeBuf = Buffer.alloc(8);     feeBuf.writeBigUInt64LE(0n);
  const claimData = Buffer.concat([
    disc("claim"),                 // 8  — discriminator for the retired ix
    Buffer.alloc(256),             // proof (a|b|c), dummy
    Buffer.alloc(32),              // merkle_root
    nullifierHash,                 // nullifier_hash
    amountBuf,                     // amount
    Buffer.alloc(32),              // amount_commitment
    Buffer.alloc(32),              // password_hash
    feeBuf,                        // fee_lamports
  ]);

  const claimIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: false },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: nullifierPDA, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: claimData,
  });

  console.log(`  Program:        ${PROGRAM_ID}`);
  console.log(`  claim discrim.: ${disc("claim").toString("hex")}`);
  console.log("  Submitting a V1 `claim` instruction (expected to be rejected as unknown)...\n");

  let succeeded = false;
  let errMsg = "";
  let logs = [];
  try {
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(claimIx), [payer]);
    succeeded = true;
    console.log(`  TX UNEXPECTEDLY SUCCEEDED: ${sig}`);
  } catch (e) {
    errMsg = e.message || String(e);
    logs = e.logs || [];
  }

  if (succeeded) {
    console.log("\n=== FAIL: V1 `claim` instruction was accepted — handler still present ===");
    process.exit(1);
  }

  console.log("  Rejected (as expected). Error + logs:");
  console.log(`    message: ${errMsg}`);
  logs.forEach(l => console.log(`    log: ${l}`));

  // Anchor's dispatcher returns InstructionFallbackNotFound (0x65 = 101) when
  // no handler matches the discriminator. Accept any of the equivalent
  // signatures the SDK/runtime may surface.
  const hay = (errMsg + "\n" + logs.join("\n")).toLowerCase();
  const fallbackSignatures = ["0x65", "fallback", "fallback functions are not supported",
    "instructionfallbacknotfound", "custom program error: 101", " 101"];
  const matched = fallbackSignatures.find(s => hay.includes(s));

  // Guard against false positives: a surviving handler would more likely fail
  // with an account/constraint/proof error, NOT the fallback code.
  const handlerStillThereSignatures = ["accountnotinitialized", "invalidproof",
    "invalidroot", "noncanonical", "constraintseeds", "could not deserialize"];
  const looksLikeHandler = handlerStillThereSignatures.find(s => hay.includes(s));

  if (matched && !looksLikeHandler) {
    console.log(`\n=== PASS: V1 \`claim\` rejected as unknown instruction (matched "${matched}") ===`);
    process.exit(0);
  }
  if (looksLikeHandler) {
    console.log(`\n=== FAIL: rejection looks like a live handler ("${looksLikeHandler}"), not a missing instruction ===`);
    process.exit(1);
  }
  console.log("\n=== INCONCLUSIVE: TX failed but no clear fallback signature. Review logs above. ===");
  console.log("(Treating as failure so the suite flags it for inspection.)");
  process.exit(1);
}

main().catch(e => { console.error("Fatal:", e); process.exit(1); });
