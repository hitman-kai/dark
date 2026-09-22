// Raw @solana/web3.js test for admin_sweep_spl.
//
// Setup creates a mint1 with a user deposit (1000 USDC), then mints
// 500 USDC of excess directly to the mint_vault using the test
// SPL mint's mint authority. This is the only clean way to create
// excess in the vault without bumping MintConfig.total_deposited.
//
// State at end of before():
//   mint_vault.amount = 1500 USDC
//   MintConfig.total_deposited = 1000 USDC
//   MintConfig.total_withdrawn = 0
//   outstanding = 1000 USDC
//   max_sweepable = 500 USDC
//
// Tests run in order, each mutates state. Final state is well-defined
// per test so the next test starts from a known point.

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

function makeLeaf(): Buffer {
  const buf = nodeRandomBytes(32);
  buf[0] = 0;
  return buf;
}

async function airdrop(conn: Connection, to: PublicKey, sol: number): Promise<void> {
  const sig = await conn.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
  await conn.confirmTransaction(sig, "confirmed");
}

function decodeMintConfigCounters(data: Buffer): { totalDeposited: bigint; totalWithdrawn: bigint } {
  return {
    totalDeposited: data.readBigUInt64LE(8 + 1 + 32 + 8 + 32 + 32 + 32),
    totalWithdrawn: data.readBigUInt64LE(8 + 1 + 32 + 8 + 32 + 32 + 32 + 8),
  };
}

interface MintCtx {
  mint: PublicKey;
  mintConfigPDA: PublicKey;
  mainTreePDA: PublicKey;
  poolTreePDA: PublicKey;
  mintVaultPDA: PublicKey;
}

describe("admin_sweep_spl", function () {
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

  let mint1: MintCtx;
  let mint2: MintCtx;
  let userAta1: PublicKey;
  let destAta: PublicKey;
  // Initial state from `before()`:
  //   vault holds 1500 USDC, deposits=1000, withdrawn=0, outstanding=1000
  // After running each test in order, max_sweepable changes:
  let expectedExcess = 500n * ONE_USDC;

  async function setupMintFoundation(): Promise<MintCtx> {
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

    return { mint, mintConfigPDA, mainTreePDA, poolTreePDA, mintVaultPDA };
  }

  function buildSweepIx(args: {
    mintCtx: MintCtx;
    mintVault: PublicKey;
    destination: PublicKey;
    signer: PublicKey;
    amount: bigint;
  }): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: args.mintCtx.mintConfigPDA, isSigner: false, isWritable: false },
        { pubkey: args.mintVault, isSigner: false, isWritable: true },
        { pubkey: args.destination, isSigner: false, isWritable: true },
        { pubkey: args.mintCtx.mint, isSigner: false, isWritable: false },
        { pubkey: args.signer, isSigner: true, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("admin_sweep_spl"),
        u64LE(args.amount),
      ]),
    });
  }

  before(async () => {
    const info = await connection.getAccountInfo(PROGRAM_ID, "confirmed");
    if (!info || !info.executable) {
      throw new Error(`Program not deployed at ${RPC_URL}.`);
    }
    await airdrop(connection, authority.publicKey, 30);
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

    mint1 = await setupMintFoundation();
    mint2 = await setupMintFoundation();

    // User ATA on mint1 + 1000 USDC.
    userAta1 = await createAssociatedTokenAccount(connection, authority, mint1.mint, user.publicKey);
    await mintTo(connection, authority, mint1.mint, userAta1, authority, 1_000n * ONE_USDC);

    // User deposits 1000 USDC → MintConfig.total_deposited = 1000, vault = 1000.
    const leaf = makeLeaf();
    await sendAndConfirmTransaction(connection, new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: true },
          { pubkey: mint1.mintConfigPDA, isSigner: false, isWritable: true },
          { pubkey: mint1.mainTreePDA, isSigner: false, isWritable: true },
          { pubkey: mint1.mintVaultPDA, isSigner: false, isWritable: true },
          { pubkey: userAta1, isSigner: false, isWritable: true },
          { pubkey: mint1.mint, isSigner: false, isWritable: false },
          { pubkey: user.publicKey, isSigner: true, isWritable: true },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([
          anchorDiscriminator("create_drop_spl"),
          leaf,
          u64LE(1_000n * ONE_USDC),
        ]),
      })
    ), [user], { commitment: "confirmed" });

    // Mint 500 USDC directly into mint_vault to create excess.
    // This bypasses MintConfig.total_deposited (only create_drop_spl bumps that),
    // simulating the "vault accidentally received tokens / leftover from fees /
    // direct transfer" case that admin_sweep_spl exists to recover from.
    await mintTo(
      connection, authority, mint1.mint, mint1.mintVaultPDA, authority,
      500n * ONE_USDC
    );

    // Destination ATA for the admin (their own ATA on mint1).
    destAta = await createAssociatedTokenAccount(
      connection, authority, mint1.mint, authority.publicKey
    );
  });

  it("sweeps a partial amount of excess; counters unchanged", async () => {
    const sweepAmount = 300n * ONE_USDC;

    const vaultBefore = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;
    const destBefore = (await getAccount(connection, destAta, "confirmed")).amount;
    const cntBefore = decodeMintConfigCounters(
      (await connection.getAccountInfo(mint1.mintConfigPDA, "confirmed"))!.data
    );

    await sendAndConfirmTransaction(connection, new Transaction().add(
      buildSweepIx({
        mintCtx: mint1,
        mintVault: mint1.mintVaultPDA,
        destination: destAta,
        signer: authority.publicKey,
        amount: sweepAmount,
      })
    ), [authority], { commitment: "confirmed" });

    const vaultAfter = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;
    const destAfter = (await getAccount(connection, destAta, "confirmed")).amount;
    const cntAfter = decodeMintConfigCounters(
      (await connection.getAccountInfo(mint1.mintConfigPDA, "confirmed"))!.data
    );

    expect(vaultAfter).to.equal(vaultBefore - sweepAmount);
    expect(destAfter).to.equal(destBefore + sweepAmount);
    // Crucial: counters MUST NOT change on sweep.
    expect(cntAfter.totalDeposited).to.equal(cntBefore.totalDeposited);
    expect(cntAfter.totalWithdrawn).to.equal(cntBefore.totalWithdrawn);

    expectedExcess -= sweepAmount;
  });

  it("rejects sweep above max (InsufficientBalance)", async () => {
    // Excess after test 1 is 200 USDC. Try to sweep 600.
    const overAsk = 600n * ONE_USDC;

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildSweepIx({
          mintCtx: mint1,
          mintVault: mint1.mintVaultPDA,
          destination: destAta,
          signer: authority.publicKey,
          amount: overAsk,
        })
      ), [authority], { commitment: "confirmed" });
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // InsufficientBalance = errors.rs ordinal 7 → 6007 → 0x1777
    expect(errorText).to.match(
      /InsufficientBalance|6007|0x1777/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("can sweep down to exactly the user-owed floor; one more lamport-unit fails", async () => {
    // Sweep the remaining excess (200 USDC) — should succeed and put
    // the vault at exactly outstanding.
    await sendAndConfirmTransaction(connection, new Transaction().add(
      buildSweepIx({
        mintCtx: mint1,
        mintVault: mint1.mintVaultPDA,
        destination: destAta,
        signer: authority.publicKey,
        amount: expectedExcess,
      })
    ), [authority], { commitment: "confirmed" });

    const vaultAt = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;
    expect(vaultAt).to.equal(1_000n * ONE_USDC); // == outstanding

    // Now try to sweep 1 base unit — the vault is at the floor, max_sweepable = 0.
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildSweepIx({
          mintCtx: mint1,
          mintVault: mint1.mintVaultPDA,
          destination: destAta,
          signer: authority.publicKey,
          amount: 1n,
        })
      ), [authority], { commitment: "confirmed" });
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    expect(errorText).to.match(
      /InsufficientBalance|6007|0x1777/i,
      `got unexpected error text: ${errorText}`
    );

    // Vault still at the floor — invariant preserved.
    const vaultStill = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;
    expect(vaultStill).to.equal(1_000n * ONE_USDC);
    expectedExcess = 0n;
  });

  it("rejects sweep from a non-authority signer (ConstraintHasOne)", async () => {
    // Top up the vault so the test isn't trivially blocked by the floor.
    await mintTo(
      connection, authority, mint1.mint, mint1.mintVaultPDA, authority,
      100n * ONE_USDC
    );

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildSweepIx({
          mintCtx: mint1,
          mintVault: mint1.mintVaultPDA,
          destination: destAta,
          signer: stranger.publicKey,
          amount: 10n * ONE_USDC,
        })
      ), [stranger], { commitment: "confirmed" });
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    expect(errorText).to.match(
      /ConstraintHasOne|2001|0x7d1/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects using mint2's vault while passing mint1's mint_config", async () => {
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildSweepIx({
          mintCtx: mint1,                        // mint=mint1, mint_config=mint1's
          mintVault: mint2.mintVaultPDA,         // <-- mint2's vault
          destination: destAta,
          signer: authority.publicKey,
          amount: 1n,
        })
      ), [authority], { commitment: "confirmed" });
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // Either ConstraintSeeds (mint_vault seed = [b"mint_vault", mint1] vs
    // passed mint2 vault) or ConstraintHasOne (mint_config.mint_vault !=
    // passed vault). Both indicate the right kind of rejection.
    expect(errorText).to.match(
      /ConstraintSeeds|ConstraintHasOne|2001|2006|0x7d1|0x7d6/i,
      `got unexpected error text: ${errorText}`
    );
  });
});
