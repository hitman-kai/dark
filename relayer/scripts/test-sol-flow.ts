/**
 * DarkDrop V4 — Relayer SOL Flow Integration Test (devnet)
 *
 * Verifies the existing /api/relay/credit/claim + /api/relay/credit/withdraw
 * SOL endpoints work end-to-end against the test program. The relayer must
 * be started with SOL_PROGRAM_ID=8b8JX1nh... in its env so its `programId`
 * config points at the test program; otherwise the relayer hits the live
 * program and this test does not validate the new binary.
 *
 * Flow:
 *   1. Fetch /health, confirm relayer pubkey and the program ID it's using
 *      (we infer via successful TX landing — relayer doesn't currently
 *      expose its programId in /health).
 *   2. User-signs `create_drop` (NOT through the relayer — same as the SPL
 *      side, deposits are user-signed).
 *   3. Read the merkle_tree account post-deposit to snapshot the root +
 *      filled_subtrees; derive the path for our leaf.
 *   4. Generate V2 proof for the claim.
 *   5. POST to /api/relay/credit/claim.
 *   6. POST to /api/relay/credit/withdraw (rate defaults to config.feeRateBps).
 *   7. Assert recipient SOL balance increased by amount - fee.
 *
 * Run: cd relayer && TS_NODE_TRANSPILE_ONLY=1 npx ts-node --skip-project \
 *      --transpile-only scripts/test-sol-flow.ts
 *
 * The SOL_PROGRAM_ID env var here mirrors the relayer's. We default both
 * to 8b8JX1nh... so the depositor TX lands on the same program the relayer
 * is hitting.
 */

import * as fs from "fs";
import * as os from "os";
import * as http from "http";
import { createHash } from "crypto";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

import {
  initPoseidon,
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
import {
  snapshotTreeAccount,
  decodeTreeSnapshot,
  buildProofFromSnapshot,
  readTreeNextIndex,
} from "../../frontend/src/lib/merkle";

// ─── Constants ───────────────────────────────────────────────────────────
const RELAYER_URL = process.env.RELAYER_URL || "http://localhost:3001";
const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey(
  process.env.SOL_PROGRAM_ID || "8b8JX1nhcG5UryRUE6Zm85LLcTA6PjquEkUVwWRV6Rrn"
);
const WALLET_PATH = process.env.WALLET || `${os.homedir()}/.config/solana/id.json`;

const WASM_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop.wasm";
const ZKEY_V2_PATH =
  "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop_v2_final.zkey";

// 0.005 SOL — large enough that the 50 bps fee is a non-trivial integer
// (25_000 lamports), small enough to leave headroom on a long-running
// devnet wallet.
const AMOUNT_LAMPORTS = 5_000_000n;
const FEE_BPS = 50;

// ─── Helpers ─────────────────────────────────────────────────────────────
function anchorDisc(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}
function u64LE(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n, 0);
  return b;
}
function loadKeypair(p: string): Keypair {
  const data = JSON.parse(fs.readFileSync(p, "utf8")) as number[];
  return Keypair.fromSecretKey(new Uint8Array(data));
}

function postJson(url: string, body: any): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": data.length.toString(),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: any;
          try { parsed = JSON.parse(text); } catch { parsed = { raw: text }; }
          resolve({ status: res.statusCode || 0, body: parsed });
        });
      }
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

function getJson(url: string): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.get(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: any;
          try { parsed = JSON.parse(text); } catch { parsed = { raw: text }; }
          resolve({ status: res.statusCode || 0, body: parsed });
        });
      }
    );
    req.on("error", reject);
  });
}

// ─── Main ────────────────────────────────────────────────────────────────
async function main() {
  console.log(`[sol-test] relayer=${RELAYER_URL}`);
  console.log(`[sol-test] rpc=${RPC_URL}`);
  console.log(`[sol-test] program=${PROGRAM_ID.toBase58()}`);

  const health = await getJson(`${RELAYER_URL}/health`);
  if (health.status !== 200 || !health.body.relayerPubkey) {
    throw new Error(`Relayer not reachable: ${JSON.stringify(health)}`);
  }
  console.log(`[sol-test] relayer pubkey: ${health.body.relayerPubkey}`);

  const connection = new Connection(RPC_URL, "confirmed");
  const wallet = loadKeypair(WALLET_PATH);
  console.log(`[sol-test] depositor wallet: ${wallet.publicKey.toBase58()}`);

  // Fresh recipient — clean balance delta math.
  const recipient = Keypair.generate();
  console.log(`[sol-test] recipient: ${recipient.publicKey.toBase58()}`);

  // PDAs (SOL flow uses the global merkle_tree, vault, treasury — not per-mint).
  const [vaultPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault")], PROGRAM_ID
  );
  const [merkleTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vaultPDA.toBuffer()], PROGRAM_ID
  );
  const [treasuryPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("treasury")], PROGRAM_ID
  );
  console.log(`[sol-test] vault    : ${vaultPDA.toBase58()}`);
  console.log(`[sol-test] tree     : ${merkleTreePDA.toBase58()}`);
  console.log(`[sol-test] treasury : ${treasuryPDA.toBase58()}`);

  setV2ArtifactPaths(WASM_PATH, ZKEY_V2_PATH);
  await initPoseidon();

  // === Generate deposit secrets + leaf ===
  const secret = randomFieldElement();
  const nullifier = randomFieldElement();
  const blinding = randomFieldElement();
  const password = 0n;
  const amount = AMOUNT_LAMPORTS;

  const leaf = createLeaf(secret, nullifier, amount, blinding);
  const amtCommit = computeAmountCommitment(amount, blinding);
  const nullHash = computeNullifierHash(nullifier);
  const pwdHash = computePasswordHash(password);

  // === User-signed create_drop ===
  // Layout: disc(8) + leaf(32) + amount(u64 LE, 8) + amountCommit(32) + passwordHash(32)
  const createData = Buffer.concat([
    anchorDisc("create_drop"),
    Buffer.from(bigintToBytes32BE(leaf)),
    u64LE(amount),
    Buffer.from(bigintToBytes32BE(amtCommit)),
    Buffer.from(bigintToBytes32BE(pwdHash)),
  ]);

  const recipientBalBefore = await connection.getBalance(recipient.publicKey, "confirmed");
  const treasuryBalBefore = await connection.getBalance(treasuryPDA, "confirmed");

  const createSig = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: true },
          { pubkey: merkleTreePDA, isSigner: false, isWritable: true },
          { pubkey: treasuryPDA, isSigner: false, isWritable: true },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: createData,
      })
    ),
    [wallet],
    { commitment: "confirmed" }
  );
  console.log(`[sol-test] create_drop: ${createSig}`);

  // === Snapshot the tree post-deposit, derive our leaf's path ===
  const treeAccount = await connection.getAccountInfo(merkleTreePDA, "confirmed");
  if (!treeAccount) throw new Error("merkle_tree account not found after deposit");
  const nextIndex = readTreeNextIndex(treeAccount.data);
  const leafIndex = nextIndex - 1;
  console.log(`[sol-test] leaf index in tree: ${leafIndex}`);

  const snapshotB64 = snapshotTreeAccount(treeAccount.data);
  const snap = decodeTreeSnapshot(snapshotB64);
  const merkleProof = buildProofFromSnapshot(snap, leafIndex);

  // === V2 proof ===
  const salt = randomFieldElement();
  const proof = await generateClaimProofV2(
    { secret, nullifier, amount, blindingFactor: blinding, password },
    merkleProof,
    recipient.publicKey,
    nullHash,
    amtCommit,
    pwdHash
  );
  console.log(
    `[sol-test] proof generated, nullifierHash=${Buffer.from(proof.nullifierHash).toString("hex").slice(0, 16)}...`
  );

  // === Relayer /credit/claim ===
  const inputs = Buffer.concat([
    Buffer.from(proof.merkleRoot),
    Buffer.from(proof.amountCommitment),
    Buffer.from(proof.passwordHash),
  ]);

  const claimResp = await postJson(`${RELAYER_URL}/api/relay/credit/claim`, {
    proof: {
      proofA: Array.from(proof.proofA),
      proofB: Array.from(proof.proofB),
      proofC: Array.from(proof.proofC),
    },
    nullifierHash: Array.from(proof.nullifierHash),
    recipient: recipient.publicKey.toBase58(),
    inputs: Array.from(inputs),
    salt: Array.from(bigintToBytes32BE(salt)),
  });
  if (claimResp.status !== 200) {
    throw new Error(`Relayer /claim failed: ${claimResp.status} ${JSON.stringify(claimResp.body)}`);
  }
  console.log(`[sol-test] /credit/claim relayed: ${claimResp.body.signature}`);
  const claimSig = claimResp.body.signature as string;

  // === Relayer /credit/withdraw ===
  const opening = Buffer.concat([
    u64LE(amount),
    Buffer.from(bigintToBytes32BE(blinding)),
    Buffer.from(bigintToBytes32BE(salt)),
  ]);

  const withdrawResp = await postJson(`${RELAYER_URL}/api/relay/credit/withdraw`, {
    nullifierHash: Array.from(proof.nullifierHash),
    opening: Array.from(opening),
    recipient: recipient.publicKey.toBase58(),
  });
  if (withdrawResp.status !== 200) {
    throw new Error(`Relayer /withdraw failed: ${withdrawResp.status} ${JSON.stringify(withdrawResp.body)}`);
  }
  console.log(`[sol-test] /credit/withdraw relayed: ${withdrawResp.body.signature}`);
  const withdrawSig = withdrawResp.body.signature as string;

  // === Assertions ===
  const recipientBalAfter = await connection.getBalance(recipient.publicKey, "confirmed");
  const treasuryBalAfter = await connection.getBalance(treasuryPDA, "confirmed");

  const fee = (amount * BigInt(FEE_BPS)) / 10000n;
  const netExpected = amount - fee;
  const recipientDelta = BigInt(recipientBalAfter - recipientBalBefore);
  const treasuryDelta = BigInt(treasuryBalAfter - treasuryBalBefore);

  console.log(`[sol-test] amount=${amount} fee=${fee} netExpected=${netExpected}`);
  console.log(`[sol-test] recipient: ${recipientBalBefore} → ${recipientBalAfter} (Δ=${recipientDelta})`);
  console.log(`[sol-test] treasury : ${treasuryBalBefore} → ${treasuryBalAfter} (Δ=${treasuryDelta})`);

  const passRecipient = recipientDelta === netExpected;
  // Treasury net change: +amount on deposit, -amount on withdraw → 0.
  // (Fees flow to the relayer, not treasury, per I-04.)
  const passTreasury = treasuryDelta === 0n;

  console.log(`[sol-test] recipient credited by amount-fee: ${passRecipient ? "PASS" : "FAIL"}`);
  console.log(`[sol-test] treasury net change == 0       : ${passTreasury ? "PASS" : "FAIL"}`);

  console.log(`[sol-test] solscan create  : https://solscan.io/tx/${createSig}?cluster=devnet`);
  console.log(`[sol-test] solscan claim   : https://solscan.io/tx/${claimSig}?cluster=devnet`);
  console.log(`[sol-test] solscan withdraw: https://solscan.io/tx/${withdrawSig}?cluster=devnet`);

  if (!(passRecipient && passTreasury)) {
    console.error("[sol-test] ASSERTIONS FAILED");
    process.exit(1);
  }
  console.log("[sol-test] PASS");
}

main().catch((e) => {
  console.error("[sol-test] FAILED:", e?.stack || e);
  process.exit(1);
});
