// Stage 2: Bootstrap the test program on devnet.
//
// 1. initialize_vault on the new program ID
// 2. Create a test SPL mint (6 decimals — USDC-like). The "devnet USDC"
//    in the task spec is interpreted as a USDC-shaped test mint that
//    we control. Using Circle's actual devnet USDC would require a
//    working faucet for Stage 4 deposits; minting our own test token
//    is cleaner and gives the same test coverage.
// 3. initialize_mint_config / trees / vault for the test mint
// 4. Persist state to /tmp/dd-devnet-state.json so Stages 3 and 4 can
//    pick up the addresses.

import * as fs from "fs";
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
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

const PROGRAM_ID = new PublicKey("8b8JX1nhcG5UryRUE6Zm85LLcTA6PjquEkUVwWRV6Rrn");
const RPC_URL = "https://api.devnet.solana.com";
const STATE_PATH = "/tmp/dd-devnet-state.json";
const WALLET_PATH = "/home/kaisol/.config/solana/id.json";
const DROP_CAP = 100_000_000_000n; // 100 SOL / 100k tokens at 6dp

function anchorDiscriminator(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function u64LE(n: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n, 0);
  return buf;
}

function loadKeypair(path: string): Keypair {
  const data = JSON.parse(fs.readFileSync(path, "utf8")) as number[];
  return Keypair.fromSecretKey(new Uint8Array(data));
}

async function main() {
  const connection = new Connection(RPC_URL, "confirmed");
  const authority = loadKeypair(WALLET_PATH);
  console.log(`[bootstrap] authority = ${authority.publicKey.toBase58()}`);

  const [vaultPDA] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
  const [merkleTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vaultPDA.toBuffer()], PROGRAM_ID
  );
  const [treasuryPDA] = PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID);

  // --- initialize_vault ---
  const vaultInfo = await connection.getAccountInfo(vaultPDA, "confirmed");
  let initVaultSig: string;
  if (vaultInfo) {
    console.log(`[bootstrap] vault already exists at ${vaultPDA.toBase58()}`);
    initVaultSig = "(already initialized)";
  } else {
    initVaultSig = await sendAndConfirmTransaction(connection, new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: true },
          { pubkey: merkleTreePDA, isSigner: false, isWritable: true },
          { pubkey: treasuryPDA, isSigner: false, isWritable: true },
          { pubkey: authority.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([anchorDiscriminator("initialize_vault"), u64LE(DROP_CAP)]),
      })
    ), [authority], { commitment: "confirmed" });
    console.log(`[bootstrap] initialize_vault tx: ${initVaultSig}`);
  }

  // --- create test SPL mint (6 decimals, mint authority = our wallet) ---
  const testMint = await createMint(connection, authority, authority.publicKey, null, 6);
  console.log(`[bootstrap] test SPL mint created: ${testMint.toBase58()}`);

  const [mintConfigPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_config"), testMint.toBuffer()], PROGRAM_ID
  );
  const [mainTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree_spl"), testMint.toBuffer()], PROGRAM_ID
  );
  const [poolTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("note_pool_tree_spl"), testMint.toBuffer()], PROGRAM_ID
  );
  const [mintVaultPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_vault"), testMint.toBuffer()], PROGRAM_ID
  );

  // --- initialize_mint_config ---
  const initCfgSig = await sendAndConfirmTransaction(connection, new Transaction().add(
    new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: testMint, isSigner: false, isWritable: false },
        { pubkey: authority.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: anchorDiscriminator("initialize_mint_config"),
    })
  ), [authority], { commitment: "confirmed" });
  console.log(`[bootstrap] initialize_mint_config tx: ${initCfgSig}`);

  // --- initialize_mint_trees ---
  const initTreesSig = await sendAndConfirmTransaction(connection, new Transaction().add(
    new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: mainTreePDA, isSigner: false, isWritable: true },
        { pubkey: poolTreePDA, isSigner: false, isWritable: true },
        { pubkey: testMint, isSigner: false, isWritable: false },
        { pubkey: authority.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: anchorDiscriminator("initialize_mint_trees"),
    })
  ), [authority], { commitment: "confirmed" });
  console.log(`[bootstrap] initialize_mint_trees tx: ${initTreesSig}`);

  // --- initialize_mint_vault ---
  const initVaultMintSig = await sendAndConfirmTransaction(connection, new Transaction().add(
    new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: mintVaultPDA, isSigner: false, isWritable: true },
        { pubkey: testMint, isSigner: false, isWritable: false },
        { pubkey: authority.publicKey, isSigner: true, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
      ],
      data: anchorDiscriminator("initialize_mint_vault"),
    })
  ), [authority], { commitment: "confirmed" });
  console.log(`[bootstrap] initialize_mint_vault tx: ${initVaultMintSig}`);

  // Persist state for stages 3 + 4.
  const state = {
    program_id: PROGRAM_ID.toBase58(),
    rpc_url: RPC_URL,
    wallet_path: WALLET_PATH,
    sol_paths: {
      vault: vaultPDA.toBase58(),
      merkle_tree: merkleTreePDA.toBase58(),
      treasury: treasuryPDA.toBase58(),
    },
    test_mint: {
      mint: testMint.toBase58(),
      mint_config: mintConfigPDA.toBase58(),
      main_tree: mainTreePDA.toBase58(),
      pool_tree: poolTreePDA.toBase58(),
      mint_vault: mintVaultPDA.toBase58(),
    },
    txs: {
      initialize_vault: initVaultSig,
      initialize_mint_config: initCfgSig,
      initialize_mint_trees: initTreesSig,
      initialize_mint_vault: initVaultMintSig,
    },
  };
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
  console.log(`[bootstrap] state written to ${STATE_PATH}`);
  console.log(`[bootstrap] DONE`);
}

main().catch((e) => {
  console.error("[bootstrap] FAILED:", e);
  process.exit(1);
});
