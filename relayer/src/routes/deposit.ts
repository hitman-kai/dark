/**
 * DarkDrop V4 — Deposit Relay Endpoint
 *
 * POST /api/relay/create-drop
 *
 * User sends SOL to the relayer wallet via a normal system transfer (separate TX).
 * The relayer then calls create_drop with itself as the sender.
 * The user's wallet never appears in any DarkDrop transaction.
 *
 * Flow:
 *   1. Client sends { leaf, commitment, seed, depositTx } to relayer
 *   2. Relayer verifies the depositTx transferred SOL to the relayer wallet
 *   3. Relayer calls create_drop with the relayer as sender
 *   4. User's wallet is NOT in the DarkDrop TX — only the relayer
 */

import { Router, Request, Response } from "express";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { config } from "../config";
import { hasProcessedNonce, markProcessed, unmarkProcessed } from "../processed-txs";
import { verifyDepositTx, isValidNonce } from "../verify-deposit";

const router = Router();

const PROGRAM_ID = new PublicKey(config.programId);

function getVaultPDA(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID)[0];
}

function getMerkleTreePDA(vault: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vault.toBytes()],
    PROGRAM_ID
  )[0];
}

function getTreasuryPDA(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID)[0];
}

const CREATE_DROP_DISCRIMINATOR = Buffer.from([157, 142, 145, 247, 92, 73, 59, 48]);

interface DepositRelayRequest {
  leaf: number[];           // 32 bytes
  amount: string;           // lamports as string
  depositTx: string;        // signature of the SOL transfer TX from user to relayer
  payer: string;            // #19: declared source pubkey (base58) of the transfer
  nonce: string;            // #19: per-deposit single-use nonce (64 hex), committed in the tx memo
}

router.post("/", async (req: Request, res: Response) => {
  try {
    const body = req.body as DepositRelayRequest;

    // Validate required fields
    if (!body.leaf || !body.amount || !body.depositTx || !body.payer || !body.nonce) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (body.leaf.length !== 32) return res.status(400).json({ error: "leaf must be 32 bytes" });
    if (!isValidNonce(body.nonce)) {
      return res.status(400).json({ error: "nonce must be 64 lowercase hex chars (32 bytes)" });
    }

    let amount: bigint;
    try {
      amount = BigInt(body.amount);
    } catch {
      return res.status(400).json({ error: "Invalid amount" });
    }
    if (amount <= 0n) return res.status(400).json({ error: "Amount must be > 0" });
    if (amount > config.maxClaimAmount) return res.status(400).json({ error: "Amount exceeds relay limit" });

    // #19 (F3): replay is keyed on the single-use per-deposit nonce, persisted
    // with NO TTL — a nonce can never be reused, so replay fails across any window.
    if (hasProcessedNonce(body.nonce)) {
      return res.status(409).json({ error: "Deposit nonce already used" });
    }

    const relayer: Keypair = req.app.locals.relayerKeypair;
    const connection = new Connection(config.rpcUrl, "confirmed");

    // #19 (F3): bind the deposit to its source + shape. The depositTx must be a
    // purpose-built deposit: exactly a System transfer from the declared `payer`
    // to the relayer for EXACTLY `amount`, plus a memo committing the `nonce`.
    // A tx that merely credited the relayer (airdrop / fee credit / mis-send)
    // is rejected.
    const verdict = await verifyDepositTx(connection, body.depositTx, {
      payer: body.payer,
      relayer: relayer.publicKey.toString(),
      amount,
      nonce: body.nonce,
    });
    if (!verdict.ok) {
      return res.status(400).json({ error: verdict.error });
    }

    // Mark nonce as used BEFORE submitting on-chain (prevent concurrent replays)
    markProcessed(body.nonce, body.depositTx);

    // Build create_drop instruction with relayer as sender
    const vault = getVaultPDA();
    const merkleTree = getMerkleTreePDA(vault);
    const treasury = getTreasuryPDA();

    const amountBuf = Buffer.alloc(8);
    amountBuf.writeBigUInt64LE(amount);

    // Audit 06 L-01: create_drop no longer takes amount_commitment / password_hash.
    const instructionData = Buffer.concat([
      CREATE_DROP_DISCRIMINATOR,
      new Uint8Array(body.leaf),        // 32
      amountBuf,                        // 8
    ]);

    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: merkleTree, isSigner: false, isWritable: true },
        { pubkey: treasury, isSigner: false, isWritable: true },
        { pubkey: relayer.publicKey, isSigner: true, isWritable: true },  // relayer is sender
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: instructionData,
    });

    const tx = new Transaction().add(ix);
    tx.feePayer = relayer.publicKey;

    let signature: string;
    try {
      signature = await sendAndConfirmTransaction(connection, tx, [relayer], {
        commitment: "confirmed",
      });
    } catch (err) {
      // On-chain TX failed — free the nonce so the user can retry
      unmarkProcessed(body.nonce);
      throw err;
    }

    console.log(
      `Deposit relayed: ${signature} | amount=${amount} | depositTx=${body.depositTx}`
    );

    res.json({
      success: true,
      signature,
      depositTx: body.depositTx,
    });
  } catch (err: any) {
    console.error("Relay deposit error:", err.message);
    res.status(500).json({ error: "Relay failed" });
  }
});

export default router;
