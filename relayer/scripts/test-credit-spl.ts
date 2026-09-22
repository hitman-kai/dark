/**
 * DarkDrop V4 — Relayer SPL Integration Test (devnet)
 *
 * Verifies the relayer's new SPL endpoints by running a full claim+withdraw
 * flow against the devnet test program. Assumes the relayer is already
 * running on localhost:3001 (override with RELAYER_URL).
 *
 * Steps:
 *   1. Hit relayer /health to discover relayer pubkey.
 *   2. Create a fresh SPL mint (6 decimals) — empty merkle tree, simplest
 *      proof construction.
 *   3. Bootstrap that mint on the test program (mint_config / trees / vault).
 *   4. Pre-create user ATA + recipient ATA + relayer payer ATA.
 *   5. Mint tokens to user ATA.
 *   6. User-signed `create_drop_spl` deposit (NOT through the relayer —
 *      deposits stay user-signed by design).
 *   7. POST /api/relay/credit-spl/claim — relayer submits claim_credit_spl.
 *   8. POST /api/relay/credit-spl/withdraw — relayer submits withdraw_credit_spl.
 *   9. Assert balances and exit 0/1.
 *
 * Run: TS_NODE_TRANSPILE_ONLY=1 npx ts-node --skip-project --transpile-only \
 *      scripts/test-credit-spl.ts
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as http from "http";
import { createHash } from "crypto";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_RENT_PUBKEY,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  createMint,
  createAssociatedTokenAccountIdempotent,
  mintTo,
  getAccount,
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

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

// ─── Constants ───────────────────────────────────────────────────────────
const RELAYER_URL = process.env.RELAYER_URL || "http://localhost:3001";
const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey(
  process.env.TEST_PROGRAM_ID || "8b8JX1nhcG5UryRUE6Zm85LLcTA6PjquEkUVwWRV6Rrn"
);
const WALLET_PATH = process.env.WALLET || `${os.homedir()}/.config/solana/id.json`;

const WASM_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop.wasm";
const ZKEY_V2_PATH =
  "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop_v2_final.zkey";

const ONE_USDC = 1_000_000n; // 6 decimals
const DEPOSIT_AMOUNT = 25n * ONE_USDC;
const USER_MINT_AMOUNT = 100n * ONE_USDC;

const MERKLE_DEPTH = 20;

// ─── Helpers ─────────────────────────────────────────────────────────────
function anchorDisc(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}
function u64LE(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n, 0);
  return b;
}
function u16LE(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
}
function u32LE(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n, 0);
  return b;
}
function loadKeypair(p: string): Keypair {
  const data = JSON.parse(fs.readFileSync(p, "utf8")) as number[];
  return Keypair.fromSecretKey(new Uint8Array(data));
}

function buildEmptyTreeProof(): { pathElements: bigint[]; pathIndices: number[] } {
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

// Minimal Node http JSON POST — keeps the script free of node-fetch / axios deps.
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
        let chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: any;
          try {
            parsed = JSON.parse(text);
          } catch {
            parsed = { raw: text };
          }
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
        let chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: any;
          try {
            parsed = JSON.parse(text);
          } catch {
            parsed = { raw: text };
          }
          resolve({ status: res.statusCode || 0, body: parsed });
        });
      }
    );
    req.on("error", reject);
  });
}

// ─── Main flow ───────────────────────────────────────────────────────────
async function main() {
  console.log(`[test] relayer=${RELAYER_URL}`);
  console.log(`[test] rpc=${RPC_URL}`);
  console.log(`[test] program=${PROGRAM_ID.toBase58()}`);

  // 1. /health → relayer pubkey
  const health = await getJson(`${RELAYER_URL}/health`);
  if (health.status !== 200 || !health.body.relayerPubkey) {
    throw new Error(`Relayer not reachable / unhealthy: ${JSON.stringify(health)}`);
  }
  const relayerPubkey = new PublicKey(health.body.relayerPubkey);
  console.log(`[test] relayer pubkey: ${relayerPubkey.toBase58()}`);

  const connection = new Connection(RPC_URL, "confirmed");
  const wallet = loadKeypair(WALLET_PATH);
  console.log(`[test] admin/user wallet: ${wallet.publicKey.toBase58()}`);

  // 2. Fresh SPL mint (6 decimals, mint authority = wallet so we can mintTo)
  const mint = await createMint(connection, wallet, wallet.publicKey, null, 6);
  console.log(`[test] fresh mint: ${mint.toBase58()}`);

  // PDAs
  const [vaultPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault")], PROGRAM_ID
  );
  const [mintConfigPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_config"), mint.toBuffer()], PROGRAM_ID
  );
  const [mainTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree_spl"), mint.toBuffer()], PROGRAM_ID
  );
  const [poolTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("note_pool_tree_spl"), mint.toBuffer()], PROGRAM_ID
  );
  const [mintVaultPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_vault"), mint.toBuffer()], PROGRAM_ID
  );

  // 3. Bootstrap this mint on the test program.
  const initCfgSig = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: false },
          { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: anchorDisc("initialize_mint_config"),
      })
    ),
    [wallet],
    { commitment: "confirmed" }
  );
  console.log(`[test] initialize_mint_config: ${initCfgSig}`);

  const initTreesSig = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: false },
          { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
          { pubkey: mainTreePDA, isSigner: false, isWritable: true },
          { pubkey: poolTreePDA, isSigner: false, isWritable: true },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: anchorDisc("initialize_mint_trees"),
      })
    ),
    [wallet],
    { commitment: "confirmed" }
  );
  console.log(`[test] initialize_mint_trees: ${initTreesSig}`);

  const initVaultSig = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: false },
          { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
          { pubkey: mintVaultPDA, isSigner: false, isWritable: true },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
        ],
        data: anchorDisc("initialize_mint_vault"),
      })
    ),
    [wallet],
    { commitment: "confirmed" }
  );
  console.log(`[test] initialize_mint_vault: ${initVaultSig}`);

  // 4. Recipient + ATAs. Recipient is a fresh keypair we never sign with —
  // it's a destination only.
  const recipient = Keypair.generate();
  console.log(`[test] recipient wallet: ${recipient.publicKey.toBase58()}`);

  const userAta = await createAssociatedTokenAccountIdempotent(
    connection, wallet, mint, wallet.publicKey
  );
  console.log(`[test] user ATA: ${userAta.toBase58()}`);

  const recipientAta = await createAssociatedTokenAccountIdempotent(
    connection, wallet, mint, recipient.publicKey
  );
  console.log(`[test] recipient ATA: ${recipientAta.toBase58()}`);

  // Pre-create relayer's payer ATA. Required by withdraw_credit_spl even at
  // rate=0 (Anchor parses + validates it). In this test env the relayer key
  // equals the wallet key, so this ATA is byte-for-byte the same account as
  // userAta — the idempotent call just no-ops, and that's fine: the wallet
  // genuinely plays both depositor and payer roles in the test, exactly as
  // it would in prod if a relayer operator were also a user.
  const payerAta = await createAssociatedTokenAccountIdempotent(
    connection, wallet, mint, relayerPubkey
  );
  console.log(`[test] relayer payer ATA: ${payerAta.toBase58()}`);

  // 5. Mint 100 test-USDC to user
  const mintToSig = await mintTo(
    connection, wallet, mint, userAta, wallet, Number(USER_MINT_AMOUNT)
  );
  console.log(`[test] mintTo user: ${mintToSig}`);

  // 6. Generate deposit secrets + leaf
  setV2ArtifactPaths(WASM_PATH, ZKEY_V2_PATH);
  await initPoseidon();

  const secret = randomFieldElement();
  const nullifier = randomFieldElement();
  const blinding = randomFieldElement();
  const password = 0n;
  const amount = DEPOSIT_AMOUNT;

  const leaf = createLeaf(secret, nullifier, amount, blinding);
  const amtCommit = computeAmountCommitment(amount, blinding);
  const nullHash = computeNullifierHash(nullifier);
  const pwdHash = computePasswordHash(password);

  // 7. User-signed create_drop_spl (NOT through relayer)
  const userBalBefore = (await getAccount(connection, userAta, "confirmed")).amount;
  const mintVaultBalBefore = (await getAccount(connection, mintVaultPDA, "confirmed")).amount;
  const recipientBalBefore = (await getAccount(connection, recipientAta, "confirmed")).amount;

  const leafBuf = Buffer.from(bigintToBytes32BE(leaf));
  const createSig = await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: true },
          { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
          { pubkey: mainTreePDA, isSigner: false, isWritable: true },
          { pubkey: mintVaultPDA, isSigner: false, isWritable: true },
          { pubkey: userAta, isSigner: false, isWritable: true },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([anchorDisc("create_drop_spl"), leafBuf, u64LE(amount)]),
      })
    ),
    [wallet],
    { commitment: "confirmed" }
  );
  console.log(`[test] create_drop_spl: ${createSig}`);

  // 8. Build V2 proof (single-leaf empty-tree merkle proof, since the SPL
  // tree was just initialized and our deposit is the first leaf).
  const root = rootForSingleLeaf(leaf);
  const { pathElements, pathIndices } = buildEmptyTreeProof();
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
  console.log(`[test] proof generated, nullifierHash=${Buffer.from(proof.nullifierHash).toString("hex").slice(0, 16)}...`);

  // 9. POST /credit-spl/claim → relayer submits claim_credit_spl
  const inputs = Buffer.concat([
    Buffer.from(proof.merkleRoot),
    Buffer.from(proof.amountCommitment),
    Buffer.from(proof.passwordHash),
  ]);

  const claimResp = await postJson(`${RELAYER_URL}/api/relay/credit-spl/claim`, {
    mint: mint.toBase58(),
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
  console.log(`[test] /credit-spl/claim relayed: ${claimResp.body.signature}`);
  const claimSig = claimResp.body.signature as string;

  // 10. POST /credit-spl/withdraw — explicit rate=0 to keep balance math clean
  const opening = Buffer.concat([
    u64LE(amount),
    Buffer.from(bigintToBytes32BE(blinding)),
    Buffer.from(bigintToBytes32BE(salt)),
  ]);

  const withdrawResp = await postJson(`${RELAYER_URL}/api/relay/credit-spl/withdraw`, {
    mint: mint.toBase58(),
    nullifierHash: Array.from(proof.nullifierHash),
    opening: Array.from(opening),
    recipient: recipient.publicKey.toBase58(),
    rate: 0,
  });
  if (withdrawResp.status !== 200) {
    throw new Error(`Relayer /withdraw failed: ${withdrawResp.status} ${JSON.stringify(withdrawResp.body)}`);
  }
  console.log(`[test] /credit-spl/withdraw relayed: ${withdrawResp.body.signature}`);
  const withdrawSig = withdrawResp.body.signature as string;

  // 11. Assertions
  const userBalAfter = (await getAccount(connection, userAta, "confirmed")).amount;
  const mintVaultBalAfter = (await getAccount(connection, mintVaultPDA, "confirmed")).amount;
  const recipientBalAfter = (await getAccount(connection, recipientAta, "confirmed")).amount;

  console.log(`[test] user ATA:      ${userBalBefore} → ${userBalAfter}`);
  console.log(`[test] mint_vault:    ${mintVaultBalBefore} → ${mintVaultBalAfter}`);
  console.log(`[test] recipient ATA: ${recipientBalBefore} → ${recipientBalAfter}`);

  const passUser = userBalAfter === userBalBefore - amount;
  const passVault = mintVaultBalAfter === mintVaultBalBefore;     // +amount on deposit, -amount on withdraw
  const passRecipient = recipientBalAfter === recipientBalBefore + amount; // rate=0

  console.log(`[test] user debited by ${amount}: ${passUser ? "PASS" : "FAIL"}`);
  console.log(`[test] mint_vault net change == 0: ${passVault ? "PASS" : "FAIL"}`);
  console.log(`[test] recipient credited by ${amount}: ${passRecipient ? "PASS" : "FAIL"}`);

  // Solscan links for manual verification
  console.log(`[test] solscan claim:    https://solscan.io/tx/${claimSig}?cluster=devnet`);
  console.log(`[test] solscan withdraw: https://solscan.io/tx/${withdrawSig}?cluster=devnet`);

  if (!(passUser && passVault && passRecipient)) {
    console.error("[test] ASSERTIONS FAILED");
    process.exit(1);
  }
  console.log("[test] PASS");
}

main().catch((e) => {
  console.error("[test] FAILED:", e?.stack || e);
  process.exit(1);
});
