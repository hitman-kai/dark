// Bootstrap Circle's official devnet USDC mint on the test program.
//
// The test program (8b8JX1nh…) already has its global Vault initialized
// from devnet-bootstrap.ts (which created a self-generated test mint).
// This script adds Circle's real devnet USDC mint
// (4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU) as a second supported
// mint so the frontend can be tested against tokens from faucet.circle.com.
//
// Per-mint admin instructions only — skips initialize_vault (per-program,
// already done) and skips createMint (mint exists on devnet, owned by Circle).
//
//   initialize_mint_config(MINT)
//   initialize_mint_trees(MINT)
//   initialize_mint_vault(MINT)
//
// All three are admin-only ixs; the admin signer is whoever ran the
// original initialize_vault — in this test setup, the wallet at
// ~/.config/solana/id.json.

import * as fs from "fs";
import * as os from "os";
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
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";

const PROGRAM_ID = new PublicKey(
  process.env.PROGRAM_ID ?? "8b8JX1nhcG5UryRUE6Zm85LLcTA6PjquEkUVwWRV6Rrn"
);
const MINT = new PublicKey("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
const RPC_URL = "https://api.devnet.solana.com";
const WALLET_PATH = `${os.homedir()}/.config/solana/id.json`;

function anchorDisc(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function loadKeypair(p: string): Keypair {
  const data = JSON.parse(fs.readFileSync(p, "utf8")) as number[];
  return Keypair.fromSecretKey(new Uint8Array(data));
}

async function accountExists(connection: Connection, pubkey: PublicKey): Promise<boolean> {
  const info = await connection.getAccountInfo(pubkey, "confirmed");
  return info !== null;
}

async function main() {
  const connection = new Connection(RPC_URL, "confirmed");
  const authority = loadKeypair(WALLET_PATH);
  console.log(`[circle-usdc] authority = ${authority.publicKey.toBase58()}`);
  console.log(`[circle-usdc] program   = ${PROGRAM_ID.toBase58()}`);
  console.log(`[circle-usdc] mint      = ${MINT.toBase58()}`);

  const [vaultPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault")], PROGRAM_ID
  );
  const [mintConfigPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_config"), MINT.toBuffer()], PROGRAM_ID
  );
  const [mainTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree_spl"), MINT.toBuffer()], PROGRAM_ID
  );
  const [poolTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("note_pool_tree_spl"), MINT.toBuffer()], PROGRAM_ID
  );
  const [mintVaultPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_vault"), MINT.toBuffer()], PROGRAM_ID
  );

  console.log(`[circle-usdc] vault PDA           = ${vaultPDA.toBase58()}`);
  console.log(`[circle-usdc] mint_config PDA     = ${mintConfigPDA.toBase58()}`);
  console.log(`[circle-usdc] merkle_tree_spl PDA = ${mainTreePDA.toBase58()}`);
  console.log(`[circle-usdc] note_pool_tree_spl  = ${poolTreePDA.toBase58()}`);
  console.log(`[circle-usdc] mint_vault PDA      = ${mintVaultPDA.toBase58()}`);

  // Sanity check: global vault must already exist on this program.
  if (!(await accountExists(connection, vaultPDA))) {
    throw new Error(
      `Global vault not initialized on ${PROGRAM_ID.toBase58()} — run devnet-bootstrap.ts first.`
    );
  }
  console.log(`[circle-usdc] confirmed global vault exists`);

  const sigs: Record<string, string> = {};

  // --- initialize_mint_config ---
  if (await accountExists(connection, mintConfigPDA)) {
    console.log(`[circle-usdc] mint_config already exists, skipping initialize_mint_config`);
    sigs.initialize_mint_config = "(already initialized)";
  } else {
    sigs.initialize_mint_config = await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: vaultPDA, isSigner: false, isWritable: false },
            { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
            { pubkey: MINT, isSigner: false, isWritable: false },
            { pubkey: authority.publicKey, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
          data: anchorDisc("initialize_mint_config"),
        })
      ),
      [authority],
      { commitment: "confirmed" }
    );
    console.log(`[circle-usdc] initialize_mint_config: ${sigs.initialize_mint_config}`);
  }

  // --- initialize_mint_trees ---
  if ((await accountExists(connection, mainTreePDA)) && (await accountExists(connection, poolTreePDA))) {
    console.log(`[circle-usdc] both trees already exist, skipping initialize_mint_trees`);
    sigs.initialize_mint_trees = "(already initialized)";
  } else {
    sigs.initialize_mint_trees = await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: vaultPDA, isSigner: false, isWritable: false },
            { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
            { pubkey: mainTreePDA, isSigner: false, isWritable: true },
            { pubkey: poolTreePDA, isSigner: false, isWritable: true },
            { pubkey: MINT, isSigner: false, isWritable: false },
            { pubkey: authority.publicKey, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
          data: anchorDisc("initialize_mint_trees"),
        })
      ),
      [authority],
      { commitment: "confirmed" }
    );
    console.log(`[circle-usdc] initialize_mint_trees: ${sigs.initialize_mint_trees}`);
  }

  // --- initialize_mint_vault ---
  if (await accountExists(connection, mintVaultPDA)) {
    console.log(`[circle-usdc] mint_vault already exists, skipping initialize_mint_vault`);
    sigs.initialize_mint_vault = "(already initialized)";
  } else {
    sigs.initialize_mint_vault = await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            { pubkey: vaultPDA, isSigner: false, isWritable: false },
            { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
            { pubkey: mintVaultPDA, isSigner: false, isWritable: true },
            { pubkey: MINT, isSigner: false, isWritable: false },
            { pubkey: authority.publicKey, isSigner: true, isWritable: true },
            { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
            { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
          ],
          data: anchorDisc("initialize_mint_vault"),
        })
      ),
      [authority],
      { commitment: "confirmed" }
    );
    console.log(`[circle-usdc] initialize_mint_vault: ${sigs.initialize_mint_vault}`);
  }

  console.log(`[circle-usdc] DONE`);
  console.log(JSON.stringify({
    program_id: PROGRAM_ID.toBase58(),
    mint: MINT.toBase58(),
    pdas: {
      vault: vaultPDA.toBase58(),
      mint_config: mintConfigPDA.toBase58(),
      merkle_tree_spl: mainTreePDA.toBase58(),
      note_pool_tree_spl: poolTreePDA.toBase58(),
      mint_vault: mintVaultPDA.toBase58(),
    },
    txs: sigs,
  }, null, 2));
}

main().catch((e) => {
  console.error("[circle-usdc] FAILED:", e);
  process.exit(1);
});
