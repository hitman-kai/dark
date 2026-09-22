/**
 * Smoke test for `frontend/src/lib/vault-spl.ts`.
 *
 * Verifies the helpers produce the exact PDAs that are bootstrapped on
 * devnet for Circle's USDC mint, and that `buildCreateDropSplIx` returns
 * a structurally correct instruction. No on-chain calls — purely local
 * verification against fixed expected values.
 */

import { PublicKey } from "@solana/web3.js";
import {
  SPL_PROGRAM_ID,
  DEVNET_USDC_MINT,
  MAINNET_USDC_MINT,
  USDC_DECIMALS,
  USDC_MIN_DEPOSIT,
  USDC_MAX_DEPOSIT,
  getVaultPDA,
  getMintConfigPDA,
  getMerkleTreeSplPDA,
  getMintVaultPDA,
  getNullifierSplPDA,
  getCreditNoteSplPDA,
  buildCreateDropSplIx,
} from "../src/lib/vault-spl";

const EXPECTED_DISCRIMINATOR = [41, 14, 49, 146, 164, 167, 97, 53];

const EXPECTED_PDAS: Record<string, string> = {
  vault: "3umM7SY6uEbasUoS44KKExNui3mReSw911r9bbNXv3bQ",
  mint_config: "4ce2A2uuFiHHbRoQkPFRh5xqY7j37uttd2Y99M44SwG4",
  merkle_tree_spl: "MAJzWYk9bCsKaaBfL8Uyc7pYyMYsy2LJQveY8x5wCYu",
  mint_vault: "FjqZBK64bTPPccPmfHwjPR9P9oUxkrrm3r6Z4SfxpkbS",
};

let failures = 0;
function check(label: string, ok: boolean, detail?: string) {
  const tag = ok ? "PASS" : "FAIL";
  console.log(`  [${tag}] ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
}

function compareAddress(label: string, derived: PublicKey, expected: string) {
  const got = derived.toBase58();
  check(label, got === expected, `derived=${got} expected=${expected}`);
}

function main() {
  console.log(`[smoke] SPL_PROGRAM_ID = ${SPL_PROGRAM_ID.toBase58()}`);
  console.log(`[smoke] DEVNET_USDC_MINT  = ${DEVNET_USDC_MINT.toBase58()}`);
  console.log(`[smoke] MAINNET_USDC_MINT = ${MAINNET_USDC_MINT.toBase58()}`);
  console.log(`[smoke] USDC_DECIMALS=${USDC_DECIMALS} MIN=${USDC_MIN_DEPOSIT} MAX=${USDC_MAX_DEPOSIT}`);
  console.log("");

  // ─── PDA derivations ───
  console.log("== PDA derivation vs devnet bootstrap ==");
  const [vault] = getVaultPDA();
  compareAddress("vault", vault, EXPECTED_PDAS.vault);

  const [mintConfig] = getMintConfigPDA(DEVNET_USDC_MINT);
  compareAddress("mint_config", mintConfig, EXPECTED_PDAS.mint_config);

  const [merkleTreeSpl] = getMerkleTreeSplPDA(DEVNET_USDC_MINT);
  compareAddress("merkle_tree_spl", merkleTreeSpl, EXPECTED_PDAS.merkle_tree_spl);

  const [mintVault] = getMintVaultPDA(DEVNET_USDC_MINT);
  compareAddress("mint_vault", mintVault, EXPECTED_PDAS.mint_vault);

  // Nullifier + credit-note PDAs with a deterministic all-zero hash. We
  // don't have a fixed "expected" string for these (no on-chain reference)
  // — we just confirm they derive without throwing and are deterministic.
  const zeroHash = new Uint8Array(32);
  const [nullifierSpl, nullBump] = getNullifierSplPDA(DEVNET_USDC_MINT, zeroHash);
  const [creditNoteSpl, creditBump] = getCreditNoteSplPDA(DEVNET_USDC_MINT, zeroHash);
  console.log(`  [INFO] nullifier_spl(0x00..) = ${nullifierSpl.toBase58()} bump=${nullBump}`);
  console.log(`  [INFO] credit_note_spl(0x00..) = ${creditNoteSpl.toBase58()} bump=${creditBump}`);
  check(
    "nullifier_spl and credit_note_spl are distinct",
    nullifierSpl.toBase58() !== creditNoteSpl.toBase58()
  );

  // ─── Instruction structure ───
  console.log("");
  console.log("== buildCreateDropSplIx structure ==");

  // Fixed dummy inputs so the encoding is deterministic.
  const user = new PublicKey("11111111111111111111111111111112");
  const userAta = new PublicKey("11111111111111111111111111111113");
  const testLeaf = new Uint8Array(32);
  for (let i = 0; i < 32; i++) testLeaf[i] = (i + 1) & 0xff;
  const testAmount = 25_000_000n; // 25 USDC at 6dp

  const ix = buildCreateDropSplIx({
    user,
    userAta,
    mint: DEVNET_USDC_MINT,
    leaf: testLeaf,
    amount: testAmount,
  });

  check("programId matches SPL_PROGRAM_ID", ix.programId.equals(SPL_PROGRAM_ID));
  check("keys.length === 9", ix.keys.length === 9, `got ${ix.keys.length}`);
  check("data.length === 48", ix.data.length === 48, `got ${ix.data.length}`);

  // Discriminator at offset 0..8
  const disc = Array.from(ix.data.slice(0, 8));
  check(
    `discriminator matches [${EXPECTED_DISCRIMINATOR.join(", ")}]`,
    JSON.stringify(disc) === JSON.stringify(EXPECTED_DISCRIMINATOR),
    `got [${disc.join(", ")}]`
  );

  // Leaf at offset 8..40
  const leafOut = Array.from(ix.data.slice(8, 40));
  const leafExp = Array.from(testLeaf);
  check(
    "leaf encoded at offset [8..40]",
    JSON.stringify(leafOut) === JSON.stringify(leafExp)
  );

  // Amount at offset 40..48, u64 LE
  const amountOut = ix.data.readBigUInt64LE(40);
  check(
    "amount encoded as u64 LE at offset [40..48]",
    amountOut === testAmount,
    `got ${amountOut} expected ${testAmount}`
  );

  // Account ordering (matches create_drop_spl.rs CreateDropSpl struct)
  const expectedAccountOrder = [
    { label: "vault", pubkey: vault.toBase58(), signer: false, writable: true },
    { label: "mint_config", pubkey: mintConfig.toBase58(), signer: false, writable: true },
    { label: "merkle_tree_spl", pubkey: merkleTreeSpl.toBase58(), signer: false, writable: true },
    { label: "mint_vault", pubkey: mintVault.toBase58(), signer: false, writable: true },
    { label: "user_ata", pubkey: userAta.toBase58(), signer: false, writable: true },
    { label: "mint", pubkey: DEVNET_USDC_MINT.toBase58(), signer: false, writable: false },
    { label: "user", pubkey: user.toBase58(), signer: true, writable: true },
    { label: "token_program", pubkey: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", signer: false, writable: false },
    { label: "system_program", pubkey: "11111111111111111111111111111111", signer: false, writable: false },
  ];

  for (let i = 0; i < 9; i++) {
    const got = ix.keys[i];
    const exp = expectedAccountOrder[i];
    const okPubkey = got.pubkey.toBase58() === exp.pubkey;
    const okSigner = got.isSigner === exp.signer;
    const okWritable = got.isWritable === exp.writable;
    check(
      `keys[${i}] = ${exp.label}`,
      okPubkey && okSigner && okWritable,
      `pubkey=${got.pubkey.toBase58()} signer=${got.isSigner} writable=${got.isWritable}`
    );
  }

  // Bad-input guard
  console.log("");
  console.log("== guards ==");
  let threw = false;
  try {
    buildCreateDropSplIx({
      user,
      userAta,
      mint: DEVNET_USDC_MINT,
      leaf: new Uint8Array(31),
      amount: testAmount,
    });
  } catch {
    threw = true;
  }
  check("rejects non-32-byte leaf", threw);

  console.log("");
  if (failures > 0) {
    console.error(`[smoke] FAILED — ${failures} check(s) failed`);
    process.exit(1);
  }
  console.log(`[smoke] PASS — all checks green`);
}

main();
