// Stage 4: SPL (USDC-shaped) end-to-end flow on devnet.
//
// Deposit 50 test-USDC via create_drop_spl → V2 proof → claim_credit_spl
// → withdraw_credit_spl. Assert the recipient ATA received the tokens.
//
// Uses the test SPL mint created during Stage 2 bootstrap. The bootstrap
// script saved the mint pubkey + foundation PDAs to /tmp/dd-devnet-state.json.

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
  createAssociatedTokenAccount,
  mintTo,
  getAccount,
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

const STATE_PATH = "/tmp/dd-devnet-state.json";
const WASM_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop.wasm";
const ZKEY_V2_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop_v2_final.zkey";

const ONE_USDC = 1_000_000n; // 6 decimals
const DEPOSIT_AMOUNT = 50n * ONE_USDC;
const USER_MINT_AMOUNT = 100n * ONE_USDC;

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
  const mint = new PublicKey(state.test_mint.mint);
  const mintConfigPDA = new PublicKey(state.test_mint.mint_config);
  const mainTreePDA = new PublicKey(state.test_mint.main_tree);
  const mintVaultPDA = new PublicKey(state.test_mint.mint_vault);

  console.log(`[usdc-flow] program=${PROGRAM_ID.toBase58()}`);
  console.log(`[usdc-flow] test mint=${mint.toBase58()}`);
  console.log(`[usdc-flow] wallet=${wallet.publicKey.toBase58()}`);

  // === User and recipient setup ===
  // wallet = depositor (has SOL + can mint test tokens since it's mint authority)
  // recipient = fresh wallet that will receive the SPL withdraw
  const recipient = Keypair.generate();
  console.log(`[usdc-flow] recipient wallet=${recipient.publicKey.toBase58()}`);

  // Wallet's ATA for the test mint — depositor's token holding
  const userAta = await createAssociatedTokenAccount(connection, wallet, mint, wallet.publicKey);
  console.log(`[usdc-flow] user ATA=${userAta.toBase58()}`);

  // Mint 100 test-USDC to the depositor's ATA
  const mintToSig = await mintTo(
    connection, wallet, mint, userAta, wallet,
    Number(USER_MINT_AMOUNT)
  );
  console.log(`[usdc-flow] mintTo tx: ${mintToSig}`);

  // Recipient ATA — pays rent from our wallet, owned by recipient
  const recipientAta = await createAssociatedTokenAccount(
    connection, wallet, mint, recipient.publicKey
  );
  console.log(`[usdc-flow] recipient ATA=${recipientAta.toBase58()}`);

  // Payer ATA (= wallet's ATA, same account as user ATA in this flow since
  // the wallet plays both depositor and payer roles). For rate=0 it isn't
  // written, but Anchor still validates the account exists with correct
  // mint + owner. Reusing userAta works because wallet owns both roles.
  const payerAta = userAta;

  setV2ArtifactPaths(WASM_PATH, ZKEY_V2_PATH);
  await initPoseidon();

  // === Generate deposit secrets ===
  const secret = randomFieldElement();
  const nullifier = randomFieldElement();
  const blinding = randomFieldElement();
  const password = 0n;
  const amount = DEPOSIT_AMOUNT;

  const leaf = createLeaf(secret, nullifier, amount, blinding);
  const amtCommit = computeAmountCommitment(amount, blinding);
  const nullHash = computeNullifierHash(nullifier);
  const pwdHash = computePasswordHash(password);

  // === create_drop_spl ===
  const leafBuf = Buffer.from(bigintToBytes32BE(leaf));
  const createSplData = Buffer.concat([
    anchorDiscriminator("create_drop_spl"),
    leafBuf,
    u64LE(amount),
  ]);

  const userBalBefore = (await getAccount(connection, userAta, "confirmed")).amount;
  const mintVaultBalBefore = (await getAccount(connection, mintVaultPDA, "confirmed")).amount;
  const recipientBalBefore = (await getAccount(connection, recipientAta, "confirmed")).amount;

  const createSig = await sendAndConfirmTransaction(connection, new Transaction().add(
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
      data: createSplData,
    })
  ), [wallet], { commitment: "confirmed" });
  console.log(`[usdc-flow] create_drop_spl tx: ${createSig}`);

  // === Build merkle proof + V2 proof ===
  // The SPL tree was empty before this deposit, so the leaf is at index 0.
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

  // === claim_credit_spl ===
  const nullifierHashBuf = Buffer.from(proof.nullifierHash);
  const [nullifierSplPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier_spl"), mint.toBuffer(), nullifierHashBuf], PROGRAM_ID
  );
  const [creditNoteSplPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("credit_spl"), mint.toBuffer(), nullifierHashBuf], PROGRAM_ID
  );

  const inputs = Buffer.concat([
    Buffer.from(proof.merkleRoot),
    Buffer.from(proof.amountCommitment),
    Buffer.from(proof.passwordHash),
  ]);
  const saltBuf = Buffer.from(bigintToBytes32BE(salt));
  const claimData = Buffer.concat([
    anchorDiscriminator("claim_credit_spl"),
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
        { pubkey: mintConfigPDA, isSigner: false, isWritable: false },
        { pubkey: mainTreePDA, isSigner: false, isWritable: false },
        { pubkey: nullifierSplPDA, isSigner: false, isWritable: true },
        { pubkey: creditNoteSplPDA, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
        { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: claimData,
    })
  ), [wallet], { commitment: "confirmed" });
  console.log(`[usdc-flow] claim_credit_spl tx: ${claimSig}`);

  // === withdraw_credit_spl ===
  const opening = Buffer.concat([
    u64LE(amount),
    Buffer.from(bigintToBytes32BE(blinding)),
    saltBuf,
  ]);
  const withdrawData = Buffer.concat([
    anchorDiscriminator("withdraw_credit_spl"),
    nullifierHashBuf,
    u32LE(opening.length),
    opening,
    u16LE(0), // rate = 0
  ]);

  const withdrawSig = await sendAndConfirmTransaction(connection, new Transaction().add(
    new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: creditNoteSplPDA, isSigner: false, isWritable: true },
        { pubkey: mintVaultPDA, isSigner: false, isWritable: true },
        { pubkey: recipientAta, isSigner: false, isWritable: true },
        { pubkey: payerAta, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: withdrawData,
    })
  ), [wallet], { commitment: "confirmed" });
  console.log(`[usdc-flow] withdraw_credit_spl tx: ${withdrawSig}`);

  // === Assertions ===
  const userBalAfter = (await getAccount(connection, userAta, "confirmed")).amount;
  const mintVaultBalAfter = (await getAccount(connection, mintVaultPDA, "confirmed")).amount;
  const recipientBalAfter = (await getAccount(connection, recipientAta, "confirmed")).amount;

  console.log(`[usdc-flow] user ATA: ${userBalBefore} → ${userBalAfter}`);
  console.log(`[usdc-flow] mint_vault: ${mintVaultBalBefore} → ${mintVaultBalAfter}`);
  console.log(`[usdc-flow] recipient ATA: ${recipientBalBefore} → ${recipientBalAfter}`);

  const passUserDebit = userBalAfter === userBalBefore - amount;
  const passVaultNet = mintVaultBalAfter === mintVaultBalBefore;       // +amount on deposit, -amount on withdraw → net 0
  const passRecipient = recipientBalAfter === recipientBalBefore + amount;

  console.log(`[usdc-flow] assert user debited by ${amount}: ${passUserDebit ? "PASS" : "FAIL"}`);
  console.log(`[usdc-flow] assert mint_vault net change == 0: ${passVaultNet ? "PASS" : "FAIL"}`);
  console.log(`[usdc-flow] assert recipient ATA credited by ${amount}: ${passRecipient ? "PASS" : "FAIL"}`);

  const stateNow = JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
  stateNow.usdc_flow = {
    recipient: recipient.publicKey.toBase58(),
    user_ata: userAta.toBase58(),
    recipient_ata: recipientAta.toBase58(),
    amount: amount.toString(),
    mint_to_user: mintToSig,
    create_drop_spl: createSig,
    claim_credit_spl: claimSig,
    withdraw_credit_spl: withdrawSig,
    user_debit: (userBalBefore - userBalAfter).toString(),
    recipient_credit: (recipientBalAfter - recipientBalBefore).toString(),
    pass: passUserDebit && passVaultNet && passRecipient,
  };
  fs.writeFileSync(STATE_PATH, JSON.stringify(stateNow, null, 2));

  if (!(passUserDebit && passVaultNet && passRecipient)) {
    console.error("[usdc-flow] ASSERTIONS FAILED");
    process.exit(1);
  }
  console.log("[usdc-flow] DONE");
}

main().catch((e) => {
  console.error("[usdc-flow] FAILED:", e);
  process.exit(1);
});
