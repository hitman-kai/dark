// Raw @solana/web3.js test for pause_deposits.
//
// Setup: full SPL foundation for mint1 + user balance. The tests run
// in order; each one observes and mutates MintConfig.paused. The final
// test re-enables a previously-failing deposit, proving the kill-switch
// is reversible.

import { expect } from "chai";
import { createHash, randomBytes as nodeRandomBytes } from "crypto";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_RENT_PUBKEY,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
  createMint,
  createAssociatedTokenAccount,
  mintTo,
  getAccount,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const RPC_URL = "http://127.0.0.1:8899";
const DROP_CAP = 100_000_000_000n;
const ONE_USDC = 1_000_000n;

function anchorDiscriminator(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function u64LE(n: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n, 0);
  return buf;
}

/** 32-byte leaf with top byte forced to 0 — keeps Poseidon happy. */
function makeLeaf(): Buffer {
  const buf = nodeRandomBytes(32);
  buf[0] = 0;
  return buf;
}

async function airdrop(conn: Connection, to: PublicKey, sol: number): Promise<void> {
  const sig = await conn.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
  await conn.confirmTransaction(sig, "confirmed");
}

function decodeMintConfigPaused(data: Buffer): boolean {
  // Layout: disc(8) bump(1) mint(32) registered_at(8) merkle_tree(32) note_pool_tree(32)
  //   mint_vault(32) total_deposited(8) total_withdrawn(8) paused(1)
  return data[8 + 1 + 32 + 8 + 32 + 32 + 32 + 8 + 8] === 1;
}

function decodeMintConfigTotalDeposited(data: Buffer): bigint {
  return data.readBigUInt64LE(8 + 1 + 32 + 8 + 32 + 32 + 32);
}

function decodeTreeNextIndex(data: Buffer): number {
  // MerkleTreeSpl: disc(8) vault(32) mint(32) next_index(u32)
  return data.readUInt32LE(8 + 32 + 32);
}

describe("pause_deposits", function () {
  this.timeout(120_000);

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.generate();
  const stranger = Keypair.generate();
  const user = Keypair.generate();

  const [vaultPDA] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
  const [merkleTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vaultPDA.toBuffer()],
    PROGRAM_ID
  );
  const [treasuryPDA] = PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID);

  let mint: PublicKey;
  let mintConfigPDA: PublicKey;
  let mainTreePDA: PublicKey;
  let mintVaultPDA: PublicKey;
  let userAta: PublicKey;

  function buildPauseIx(paused: boolean, signer: PublicKey): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: signer, isSigner: true, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("pause_deposits"),
        Buffer.from([paused ? 1 : 0]),
      ]),
    });
  }

  function buildDepositIx(leaf: Buffer, amount: bigint): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: mainTreePDA, isSigner: false, isWritable: true },
        { pubkey: mintVaultPDA, isSigner: false, isWritable: true },
        { pubkey: userAta, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: user.publicKey, isSigner: true, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([anchorDiscriminator("create_drop_spl"), leaf, u64LE(amount)]),
    });
  }

  before(async () => {
    const info = await connection.getAccountInfo(PROGRAM_ID, "confirmed");
    if (!info || !info.executable) {
      throw new Error(`Program not deployed at ${RPC_URL}.`);
    }
    await airdrop(connection, authority.publicKey, 20);
    await airdrop(connection, stranger.publicKey, 1);
    await airdrop(connection, user.publicKey, 2);

    // initialize_vault
    await sendAndConfirmTransaction(connection, new Transaction().add(
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

    // mint + foundation
    mint = await createMint(connection, authority, authority.publicKey, null, 6);
    [mintConfigPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_config"), mint.toBuffer()],
      PROGRAM_ID
    );
    [mainTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree_spl"), mint.toBuffer()],
      PROGRAM_ID
    );
    [mintVaultPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_vault"), mint.toBuffer()],
      PROGRAM_ID
    );
    const [poolTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_pool_tree_spl"), mint.toBuffer()],
      PROGRAM_ID
    );

    await sendAndConfirmTransaction(connection, new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: false },
          { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: authority.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: anchorDiscriminator("initialize_mint_config"),
      })
    ), [authority], { commitment: "confirmed" });

    await sendAndConfirmTransaction(connection, new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: false },
          { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
          { pubkey: mainTreePDA, isSigner: false, isWritable: true },
          { pubkey: poolTreePDA, isSigner: false, isWritable: true },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: authority.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: anchorDiscriminator("initialize_mint_trees"),
      })
    ), [authority], { commitment: "confirmed" });

    await sendAndConfirmTransaction(connection, new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: false },
          { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
          { pubkey: mintVaultPDA, isSigner: false, isWritable: true },
          { pubkey: mint, isSigner: false, isWritable: false },
          { pubkey: authority.publicKey, isSigner: true, isWritable: true },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
        ],
        data: anchorDiscriminator("initialize_mint_vault"),
      })
    ), [authority], { commitment: "confirmed" });

    userAta = await createAssociatedTokenAccount(connection, authority, mint, user.publicKey);
    await mintTo(connection, authority, mint, userAta, authority, 1_000n * ONE_USDC);
  });

  it("pauses a mint", async () => {
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildPauseIx(true, authority.publicKey)),
      [authority],
      { commitment: "confirmed" }
    );

    const cfg = (await connection.getAccountInfo(mintConfigPDA, "confirmed"))!.data;
    expect(decodeMintConfigPaused(cfg)).to.equal(true);
  });

  it("unpauses a mint", async () => {
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildPauseIx(false, authority.publicKey)),
      [authority],
      { commitment: "confirmed" }
    );

    const cfg = (await connection.getAccountInfo(mintConfigPDA, "confirmed"))!.data;
    expect(decodeMintConfigPaused(cfg)).to.equal(false);
  });

  it("rejects pause from a non-authority signer (ConstraintHasOne)", async () => {
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildPauseIx(true, stranger.publicKey)),
        [stranger],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // ConstraintHasOne = 2001 / 0x7d1
    expect(errorText).to.match(
      /ConstraintHasOne|2001|0x7d1/i,
      `got unexpected error text: ${errorText}`
    );

    // State should be untouched (still unpaused from prior test).
    const cfg = (await connection.getAccountInfo(mintConfigPDA, "confirmed"))!.data;
    expect(decodeMintConfigPaused(cfg)).to.equal(false);
  });

  it("idempotent pause: calling pause(true) twice succeeds", async () => {
    // First pause — flips to true.
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildPauseIx(true, authority.publicKey)),
      [authority],
      { commitment: "confirmed" }
    );
    // Second pause — already true; must still succeed.
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildPauseIx(true, authority.publicKey)),
      [authority],
      { commitment: "confirmed" }
    );

    const cfg = (await connection.getAccountInfo(mintConfigPDA, "confirmed"))!.data;
    expect(decodeMintConfigPaused(cfg)).to.equal(true);
  });

  it("blocks create_drop_spl when the mint is paused (MintPaused)", async () => {
    // State entering this test: paused (from the idempotent test above).
    const leaf = makeLeaf();

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildDepositIx(leaf, 100n * ONE_USDC)),
        [user],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // MintPaused = errors.rs ordinal 23 → 6023 → 0x1787
    expect(errorText).to.match(
      /MintPaused|6023|0x1787/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("unpausing restores deposits; the previously-failing deposit now succeeds", async () => {
    // Snapshot pre-unpause state so we can verify post-deposit deltas.
    const cfgBefore = (await connection.getAccountInfo(mintConfigPDA, "confirmed"))!.data;
    const totalDepositedBefore = decodeMintConfigTotalDeposited(cfgBefore);
    const treeBefore = (await connection.getAccountInfo(mainTreePDA, "confirmed"))!.data;
    const nextIndexBefore = decodeTreeNextIndex(treeBefore);
    const vaultTokBefore = (await getAccount(connection, mintVaultPDA, "confirmed")).amount;
    const userTokBefore = (await getAccount(connection, userAta, "confirmed")).amount;

    // Unpause.
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildPauseIx(false, authority.publicKey)),
      [authority],
      { commitment: "confirmed" }
    );
    const cfgMid = (await connection.getAccountInfo(mintConfigPDA, "confirmed"))!.data;
    expect(decodeMintConfigPaused(cfgMid)).to.equal(false);

    // The same deposit that failed in the previous test now succeeds.
    const amount = 100n * ONE_USDC;
    const leaf = makeLeaf();
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildDepositIx(leaf, amount)),
      [user],
      { commitment: "confirmed" }
    );

    const cfgAfter = (await connection.getAccountInfo(mintConfigPDA, "confirmed"))!.data;
    expect(decodeMintConfigTotalDeposited(cfgAfter)).to.equal(totalDepositedBefore + amount);

    const treeAfter = (await connection.getAccountInfo(mainTreePDA, "confirmed"))!.data;
    expect(decodeTreeNextIndex(treeAfter)).to.equal(nextIndexBefore + 1);

    const vaultTokAfter = (await getAccount(connection, mintVaultPDA, "confirmed")).amount;
    expect(vaultTokAfter).to.equal(vaultTokBefore + amount);

    const userTokAfter = (await getAccount(connection, userAta, "confirmed")).amount;
    expect(userTokAfter).to.equal(userTokBefore - amount);
  });
});
