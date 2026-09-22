/**
 * DarkDrop V4 — SPL (per-mint) On-chain Helpers
 *
 * Mirrors `lib/vault.ts` for the SPL flow. PDA seeds match the program-side
 * `create_drop_spl` / `claim_credit_spl` / `withdraw_credit_spl` account
 * structs; the discriminator and account list for `create_drop_spl` match
 * `program/programs/darkdrop/src/instructions/create_drop_spl.rs`.
 *
 * Strictly additive — does not import from or modify `vault.ts`.
 */

import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";

// ─── Section A: Constants & config ───────────────────────────────────────

/**
 * Program ID for SPL routes. Points at the devnet test program until the
 * live program is upgraded with USDC support; override with
 * `NEXT_PUBLIC_TEST_PROGRAM_ID`. The SOL `PROGRAM_ID` in `vault.ts` stays
 * pinned to the live program.
 */
export const SPL_PROGRAM_ID = new PublicKey(
  process.env.NEXT_PUBLIC_TEST_PROGRAM_ID ||
    "8b8JX1nhcG5UryRUE6Zm85LLcTA6PjquEkUVwWRV6Rrn"
);

/** Circle's official devnet USDC mint. */
export const DEVNET_USDC_MINT = new PublicKey(
  "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
);

/** Circle's mainnet USDC mint. */
export const MAINNET_USDC_MINT = new PublicKey(
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
);

export const USDC_DECIMALS = 6;

/** Minimum deposit in token base units (0.01 USDC at 6 decimals). */
export const USDC_MIN_DEPOSIT = 10_000n;

/**
 * Maximum deposit in token base units (100,000 USDC at 6 decimals).
 * Matches the program-side `Vault.drop_cap` numeric bound; the on-chain
 * cap is denominated in raw base units, so the SOL `100 SOL` value and
 * this SPL `100,000 USDC` value are the same `drop_cap = 100_000_000_000`.
 */
export const USDC_MAX_DEPOSIT = 100_000_000_000n;

// ─── Section B: PDA helpers ──────────────────────────────────────────────

export function getVaultPDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("vault")],
    SPL_PROGRAM_ID
  );
}

export function getMintConfigPDA(mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("mint_config"), mint.toBuffer()],
    SPL_PROGRAM_ID
  );
}

export function getMerkleTreeSplPDA(mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree_spl"), mint.toBuffer()],
    SPL_PROGRAM_ID
  );
}

export function getMintVaultPDA(mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("mint_vault"), mint.toBuffer()],
    SPL_PROGRAM_ID
  );
}

export function getNullifierSplPDA(
  mint: PublicKey,
  nullifierHash: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier_spl"), mint.toBuffer(), nullifierHash],
    SPL_PROGRAM_ID
  );
}

export function getCreditNoteSplPDA(
  mint: PublicKey,
  nullifierHash: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("credit_spl"), mint.toBuffer(), nullifierHash],
    SPL_PROGRAM_ID
  );
}

// ─── Section C: create_drop_spl ix builder ──────────────────────────────

// sha256("global:create_drop_spl")[0..8]
// Hardcoded to keep the bundle free of a runtime crypto.subtle.digest call
// in the hot path; cross-checked by the program's Anchor discriminator.
const CREATE_DROP_SPL_DISCRIMINATOR = new Uint8Array([
  41, 14, 49, 146, 164, 167, 97, 53,
]);

export interface BuildCreateDropSplArgs {
  user: PublicKey;
  userAta: PublicKey;
  mint: PublicKey;
  leaf: Uint8Array; // 32 bytes, big-endian field element
  amount: bigint; // u64 in token base units
}

/**
 * Build a user-signed `create_drop_spl` instruction. Account order and ix
 * data layout mirror `instructions/create_drop_spl.rs`.
 */
export function buildCreateDropSplIx(
  args: BuildCreateDropSplArgs
): TransactionInstruction {
  if (args.leaf.length !== 32) {
    throw new Error(`leaf must be 32 bytes, got ${args.leaf.length}`);
  }

  const [vault] = getVaultPDA();
  const [mintConfig] = getMintConfigPDA(args.mint);
  const [merkleTreeSpl] = getMerkleTreeSplPDA(args.mint);
  const [mintVault] = getMintVaultPDA(args.mint);

  // Layout: disc(8) + leaf(32) + amount(u64 LE, 8)
  const data = new Uint8Array(8 + 32 + 8);
  data.set(CREATE_DROP_SPL_DISCRIMINATOR, 0);
  data.set(args.leaf, 8);
  new DataView(data.buffer).setBigUint64(40, args.amount, true);

  return new TransactionInstruction({
    programId: SPL_PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: mintConfig, isSigner: false, isWritable: true },
      { pubkey: merkleTreeSpl, isSigner: false, isWritable: true },
      { pubkey: mintVault, isSigner: false, isWritable: true },
      { pubkey: args.userAta, isSigner: false, isWritable: true },
      { pubkey: args.mint, isSigner: false, isWritable: false },
      { pubkey: args.user, isSigner: true, isWritable: true },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}
