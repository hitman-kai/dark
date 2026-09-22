// Raw @solana/web3.js test for create_drop_to_pool_spl.
//
// Setup: foundation chain for mint1 + mint2, user funded with tokens on
// both. Pool params (secret/nullifier/blinding) are generated as field-
// valid 32-byte buffers (top byte zeroed) so Poseidon doesn't panic.
//
// Tests are ordered so mint1 is only paused in the very last test —
// avoids needing to unpause between cases.

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
const MIN_DEPOSIT = 10_000n;
const ONE_USDC = 1_000_000n;

function anchorDiscriminator(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function u64LE(n: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n, 0);
  return buf;
}

function u32LE(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(n, 0);
  return buf;
}

/** Field-valid 32-byte buffer — top byte zeroed so the value < BN254 prime.
 *  Pool params get hashed by Poseidon on-chain; out-of-field inputs panic. */
function fieldBytes(): Buffer {
  const buf = nodeRandomBytes(32);
  buf[0] = 0;
  return buf;
}

function makePoolParams(): Buffer {
  return Buffer.concat([fieldBytes(), fieldBytes(), fieldBytes()]);
}

async function airdrop(conn: Connection, to: PublicKey, sol: number): Promise<void> {
  const sig = await conn.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
  await conn.confirmTransaction(sig, "confirmed");
}

function decodeMintConfigTotalDeposited(data: Buffer): bigint {
  return data.readBigUInt64LE(8 + 1 + 32 + 8 + 32 + 32 + 32);
}

function decodeTreeNextIndex(data: Buffer): number {
  return data.readUInt32LE(8 + 32 + 32);
}

interface MintCtx {
  mint: PublicKey;
  mintConfigPDA: PublicKey;
  mainTreePDA: PublicKey;
  poolTreePDA: PublicKey;
  mintVaultPDA: PublicKey;
  userAta: PublicKey;
}

describe("create_drop_to_pool_spl", function () {
  this.timeout(120_000);

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.generate();
  const user = Keypair.generate();

  const [vaultPDA] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
  const [merkleTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vaultPDA.toBuffer()],
    PROGRAM_ID
  );
  const [treasuryPDA] = PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID);

  let mint1: MintCtx;
  let mint2: MintCtx;

  async function setupMintFoundation(userBalance: bigint): Promise<MintCtx> {
    const mint = await createMint(connection, authority, authority.publicKey, null, 6);
    const [mintConfigPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_config"), mint.toBuffer()],
      PROGRAM_ID
    );
    const [mainTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree_spl"), mint.toBuffer()],
      PROGRAM_ID
    );
    const [poolTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_pool_tree_spl"), mint.toBuffer()],
      PROGRAM_ID
    );
    const [mintVaultPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_vault"), mint.toBuffer()],
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

    const userAta = await createAssociatedTokenAccount(connection, authority, mint, user.publicKey);
    await mintTo(connection, authority, mint, userAta, authority, userBalance);

    return { mint, mintConfigPDA, mainTreePDA, poolTreePDA, mintVaultPDA, userAta };
  }

  function buildPoolDepositIx(m: MintCtx, amount: bigint, params: Buffer): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: m.mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: m.poolTreePDA, isSigner: false, isWritable: true },
        { pubkey: m.mintVaultPDA, isSigner: false, isWritable: true },
        { pubkey: m.userAta, isSigner: false, isWritable: true },
        { pubkey: m.mint, isSigner: false, isWritable: false },
        { pubkey: user.publicKey, isSigner: true, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("create_drop_to_pool_spl"),
        u64LE(amount),
        u32LE(params.length),
        params,
      ]),
    });
  }

  function buildPauseIx(mint: PublicKey, mintConfigPDA: PublicKey, paused: boolean): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: authority.publicKey, isSigner: true, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("pause_deposits"),
        Buffer.from([paused ? 1 : 0]),
      ]),
    });
  }

  before(async () => {
    const info = await connection.getAccountInfo(PROGRAM_ID, "confirmed");
    if (!info || !info.executable) {
      throw new Error(`Program not deployed at ${RPC_URL}.`);
    }
    await airdrop(connection, authority.publicKey, 50);
    await airdrop(connection, user.publicKey, 5);

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

    mint1 = await setupMintFoundation(10_000n * ONE_USDC);
    mint2 = await setupMintFoundation(100n * ONE_USDC);
  });

  it("happy path: deposits to pool, advances pool tree, leaves main tree alone", async () => {
    const amount = 100n * ONE_USDC;
    const userBefore = (await getAccount(connection, mint1.userAta, "confirmed")).amount;
    const vaultBefore = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;
    const cfgBefore = decodeMintConfigTotalDeposited(
      (await connection.getAccountInfo(mint1.mintConfigPDA, "confirmed"))!.data
    );
    const poolNextBefore = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.poolTreePDA, "confirmed"))!.data
    );
    const mainNextBefore = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.mainTreePDA, "confirmed"))!.data
    );

    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildPoolDepositIx(mint1, amount, makePoolParams())),
      [user],
      { commitment: "confirmed" }
    );

    const userAfter = (await getAccount(connection, mint1.userAta, "confirmed")).amount;
    const vaultAfter = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;
    const cfgAfter = decodeMintConfigTotalDeposited(
      (await connection.getAccountInfo(mint1.mintConfigPDA, "confirmed"))!.data
    );
    const poolNextAfter = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.poolTreePDA, "confirmed"))!.data
    );
    const mainNextAfter = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.mainTreePDA, "confirmed"))!.data
    );

    expect(userAfter).to.equal(userBefore - amount);
    expect(vaultAfter).to.equal(vaultBefore + amount);
    expect(cfgAfter).to.equal(cfgBefore + amount);
    expect(poolNextAfter).to.equal(poolNextBefore + 1);
    expect(mainNextAfter).to.equal(mainNextBefore); // explicit: main tree did NOT move
  });

  it("rejects amount below MIN_DEPOSIT (BelowMinDeposit)", async () => {
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildPoolDepositIx(mint1, MIN_DEPOSIT - 1n, makePoolParams())),
        [user],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    expect(errorText).to.match(
      /BelowMinDeposit|6012|0x177c/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects amount above drop_cap (AmountExceedsCap)", async () => {
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildPoolDepositIx(mint1, DROP_CAP + 1n, makePoolParams())),
        [user],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    expect(errorText).to.match(
      /AmountExceedsCap|6004|0x1774/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("multi-mint independence: depositing to mint2's pool leaves mint1 alone", async () => {
    // Capture mint1 state.
    const m1PoolBefore = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.poolTreePDA, "confirmed"))!.data
    );
    const m1CfgBefore = decodeMintConfigTotalDeposited(
      (await connection.getAccountInfo(mint1.mintConfigPDA, "confirmed"))!.data
    );
    const m1VaultBefore = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;

    const amount = 50n * ONE_USDC;
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildPoolDepositIx(mint2, amount, makePoolParams())),
      [user],
      { commitment: "confirmed" }
    );

    // mint2 moved.
    const m2PoolAfter = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint2.poolTreePDA, "confirmed"))!.data
    );
    expect(m2PoolAfter).to.equal(1);
    const m2Vault = (await getAccount(connection, mint2.mintVaultPDA, "confirmed")).amount;
    expect(m2Vault).to.equal(amount);

    // mint1 unchanged.
    const m1PoolAfter = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.poolTreePDA, "confirmed"))!.data
    );
    const m1CfgAfter = decodeMintConfigTotalDeposited(
      (await connection.getAccountInfo(mint1.mintConfigPDA, "confirmed"))!.data
    );
    const m1VaultAfter = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;
    expect(m1PoolAfter).to.equal(m1PoolBefore);
    expect(m1CfgAfter).to.equal(m1CfgBefore);
    expect(m1VaultAfter).to.equal(m1VaultBefore);
  });

  it("main tree is not advanced by pool deposits (verified across multiple pool deposits)", async () => {
    const mainBefore = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.mainTreePDA, "confirmed"))!.data
    );

    // Two more pool deposits — main tree should still be at the original index.
    for (let i = 0; i < 2; i++) {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildPoolDepositIx(mint1, 10n * ONE_USDC, makePoolParams())),
        [user],
        { commitment: "confirmed" }
      );
    }

    const mainAfter = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.mainTreePDA, "confirmed"))!.data
    );
    expect(mainAfter).to.equal(mainBefore); // strictly unchanged
  });

  it("respects the pause kill switch (MintPaused)", async () => {
    // Pause mint1.
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildPauseIx(mint1.mint, mint1.mintConfigPDA, true)),
      [authority],
      { commitment: "confirmed" }
    );

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildPoolDepositIx(mint1, 100n * ONE_USDC, makePoolParams())),
        [user],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    expect(errorText).to.match(
      /MintPaused|6023|0x1787/i,
      `got unexpected error text: ${errorText}`
    );
  });
});
