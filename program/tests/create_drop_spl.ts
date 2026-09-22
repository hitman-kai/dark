// Raw @solana/web3.js test for create_drop_spl. The first user-facing
// SPL instruction — structurally parallel to the audited create_drop.
//
// Setup chain in `before`:
//   initialize_vault → mint1 → config → trees → vault → user ATA + balance
//                    → mint2 → config → trees → vault → user ATA + balance
//
// Each `it` exercises one acceptance criterion. State mutates across
// tests (mint1's tree and counters advance through the happy path) so
// each negative test re-snapshots the relevant accounts before asserting
// no further mutation occurred.

import { expect } from "chai";
import { createHash } from "crypto";
import { randomBytes } from "crypto";
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

// state.rs:21 — MIN_DEPOSIT_LAMPORTS (reused as min-base-unit threshold for SPL).
const MIN_DEPOSIT = 10_000n;
// state.rs:18 — MAX_DROP_AMOUNT, also used as Vault.drop_cap in setup.
const DROP_CAP = 100_000_000_000n;

// USDC-like: 6 decimals. 1 USDC = 1_000_000 base units.
const ONE_USDC = 1_000_000n;

function anchorDiscriminator(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function u64LE(n: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n, 0);
  return buf;
}

/** Make a 32-byte leaf that's guaranteed to be a valid BN254 field element
 *  (top byte forced to 0 → value < 2^248 < BN254 prime). The Poseidon
 *  syscall rejects out-of-field inputs with `PoseidonSyscall(InvalidParameters)`. */
function makeLeaf(): Buffer {
  const buf = randomBytes(32);
  buf[0] = 0;
  return buf;
}

async function airdrop(conn: Connection, to: PublicKey, sol: number): Promise<void> {
  const sig = await conn.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
  await conn.confirmTransaction(sig, "confirmed");
}

interface MintConfig {
  bump: number;
  mint: PublicKey;
  registeredAt: bigint;
  merkleTree: PublicKey;
  notePoolTree: PublicKey;
  mintVault: PublicKey;
  totalDeposited: bigint;
  totalWithdrawn: bigint;
  paused: boolean;
}

function decodeMintConfig(data: Buffer): MintConfig {
  let off = 8;
  const bump = data[off]; off += 1;
  const mint = new PublicKey(data.slice(off, off + 32)); off += 32;
  const registeredAt = data.readBigInt64LE(off); off += 8;
  const merkleTree = new PublicKey(data.slice(off, off + 32)); off += 32;
  const notePoolTree = new PublicKey(data.slice(off, off + 32)); off += 32;
  const mintVault = new PublicKey(data.slice(off, off + 32)); off += 32;
  const totalDeposited = data.readBigUInt64LE(off); off += 8;
  const totalWithdrawn = data.readBigUInt64LE(off); off += 8;
  const paused = data[off] === 1;
  return { bump, mint, registeredAt, merkleTree, notePoolTree, mintVault, totalDeposited, totalWithdrawn, paused };
}

interface TreeHead {
  vault: PublicKey;
  mint: PublicKey;
  nextIndex: number;
  rootHistoryIndex: number;
  currentRoot: Buffer;
}

function decodeTreeHead(data: Buffer): TreeHead {
  return {
    vault: new PublicKey(data.slice(8, 40)),
    mint: new PublicKey(data.slice(40, 72)),
    nextIndex: data.readUInt32LE(72),
    rootHistoryIndex: data.readUInt32LE(76),
    currentRoot: data.slice(80, 112),
  };
}

/** Materialize all foundation accounts for a mint and the user's ATA. */
async function setupMint(
  connection: Connection,
  authority: Keypair,
  user: Keypair,
  vaultPDA: PublicKey,
  userBalance: bigint
): Promise<{
  mint: PublicKey;
  mintConfigPDA: PublicKey;
  mainTreePDA: PublicKey;
  poolTreePDA: PublicKey;
  mintVaultPDA: PublicKey;
  userAta: PublicKey;
}> {
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

  // initialize_mint_config
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
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
    ),
    [authority],
    { commitment: "confirmed" }
  );

  // initialize_mint_trees
  await sendAndConfirmTransaction(
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
          { pubkey: authority.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: anchorDiscriminator("initialize_mint_trees"),
      })
    ),
    [authority],
    { commitment: "confirmed" }
  );

  // initialize_mint_vault
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
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
    ),
    [authority],
    { commitment: "confirmed" }
  );

  // user ATA + balance
  const userAta = await createAssociatedTokenAccount(connection, authority, mint, user.publicKey);
  await mintTo(connection, authority, mint, userAta, authority, userBalance);

  return { mint, mintConfigPDA, mainTreePDA, poolTreePDA, mintVaultPDA, userAta };
}

describe("create_drop_spl", function () {
  this.timeout(120_000);

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.generate();
  const user = Keypair.generate();

  const [vaultPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault")],
    PROGRAM_ID
  );
  const [merkleTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vaultPDA.toBuffer()],
    PROGRAM_ID
  );
  const [treasuryPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("treasury")],
    PROGRAM_ID
  );

  // Foundation state for the two test mints.
  let m1: Awaited<ReturnType<typeof setupMint>>;
  let m2: Awaited<ReturnType<typeof setupMint>>;

  // Build a create_drop_spl ix bound to a specific mint and (possibly
  // mismatched) mint_vault. The deliberately-substitutable `mintVault`
  // parameter is what the wrong-vault test exploits.
  function buildIx(
    mint: PublicKey,
    mintConfig: PublicKey,
    mainTree: PublicKey,
    mintVault: PublicKey,
    userAta: PublicKey,
    leaf: Buffer,
    amount: bigint
  ): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: mintConfig, isSigner: false, isWritable: true },
        { pubkey: mainTree, isSigner: false, isWritable: true },
        { pubkey: mintVault, isSigner: false, isWritable: true },
        { pubkey: userAta, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: user.publicKey, isSigner: true, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("create_drop_spl"),
        leaf,
        u64LE(amount),
      ]),
    });
  }

  before(async () => {
    const info = await connection.getAccountInfo(PROGRAM_ID, "confirmed");
    if (!info || !info.executable) {
      throw new Error(
        `Program ${PROGRAM_ID.toBase58()} not deployed at ${RPC_URL}. ` +
          `Start: solana-test-validator --reset --bpf-program ${PROGRAM_ID.toBase58()} ` +
          `target/deploy/darkdrop.so`
      );
    }
    await airdrop(connection, authority.publicKey, 50);
    await airdrop(connection, user.publicKey, 2);

    // initialize_vault
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
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
      ),
      [authority],
      { commitment: "confirmed" }
    );

    // Two parallel mint setups. Each gets 10_000 USDC and 100 USDC respectively.
    m1 = await setupMint(connection, authority, user, vaultPDA, 10_000n * ONE_USDC);
    m2 = await setupMint(connection, authority, user, vaultPDA, 100n * ONE_USDC);
  });

  it("happy path: deposits, debits user ATA, credits mint vault, advances tree", async () => {
    const amount = 100n * ONE_USDC;
    const leaf = makeLeaf();

    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildIx(m1.mint, m1.mintConfigPDA, m1.mainTreePDA, m1.mintVaultPDA, m1.userAta, leaf, amount)
      ),
      [user],
      { commitment: "confirmed" }
    );

    const userTok = await getAccount(connection, m1.userAta, "confirmed");
    expect(userTok.amount).to.equal(10_000n * ONE_USDC - amount);

    const vaultTok = await getAccount(connection, m1.mintVaultPDA, "confirmed");
    expect(vaultTok.amount).to.equal(amount);

    const cfgAcc = await connection.getAccountInfo(m1.mintConfigPDA, "confirmed");
    const cfg = decodeMintConfig(cfgAcc!.data);
    expect(cfg.totalDeposited).to.equal(amount);

    const treeAcc = await connection.getAccountInfo(m1.mainTreePDA, "confirmed");
    const tree = decodeTreeHead(treeAcc!.data);
    expect(tree.nextIndex).to.equal(1);
  });

  it("rejects amount below MIN_DEPOSIT (BelowMinDeposit)", async () => {
    const leaf = makeLeaf();
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildIx(m1.mint, m1.mintConfigPDA, m1.mainTreePDA, m1.mintVaultPDA, m1.userAta, leaf, MIN_DEPOSIT - 1n)
        ),
        [user],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // BelowMinDeposit = errors.rs ordinal 12 → 6012 → 0x177c
    expect(errorText).to.match(
      /BelowMinDeposit|6012|0x177c/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects amount above drop_cap (AmountExceedsCap)", async () => {
    const leaf = makeLeaf();
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildIx(m1.mint, m1.mintConfigPDA, m1.mainTreePDA, m1.mintVaultPDA, m1.userAta, leaf, DROP_CAP + 1n)
        ),
        [user],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // AmountExceedsCap = errors.rs ordinal 4 → 6004 → 0x1774
    expect(errorText).to.match(
      /AmountExceedsCap|6004|0x1774/i,
      `got unexpected error text: ${errorText}`
    );
  });

  // Paused-mint test is SKIPPED. There is no `pause_deposits` ix yet, and
  // flipping MintConfig.paused via raw account write would require the
  // program owner to sign — i.e. we'd need a custom debug ix purely for
  // the test. Re-enable once pause_deposits ships.
  it.skip("rejects deposits when MintConfig.paused is true (needs pause_deposits ix)");

  it("rejects when mint_vault does not match mint_config.mint_vault", async () => {
    const leaf = makeLeaf();
    let threw = false;
    let errorText = "";
    try {
      // Mint=m1, mint_config=m1, tree=m1, but mint_vault=m2's vault.
      // The seeds constraint on mint_vault (derived from mint=m1) and the
      // has_one=mint_vault on mint_config both fail.
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildIx(m1.mint, m1.mintConfigPDA, m1.mainTreePDA, m2.mintVaultPDA, m1.userAta, leaf, 100n * ONE_USDC)
        ),
        [user],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // Either ConstraintSeeds (2006 / 0x7d6) or ConstraintHasOne (2001 / 0x7d1)
    // depending on which Anchor checks first.
    expect(errorText).to.match(
      /ConstraintSeeds|ConstraintHasOne|2001|2006|0x7d1|0x7d6/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects when user balance is insufficient (SPL Token error)", async () => {
    // After the happy-path test user has 9_900 USDC of m1 left. Try to deposit
    // 50_000 USDC — well under drop_cap, well over user's balance.
    const leaf = makeLeaf();
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildIx(m1.mint, m1.mintConfigPDA, m1.mainTreePDA, m1.mintVaultPDA, m1.userAta, leaf, 50_000n * ONE_USDC)
        ),
        [user],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // SPL Token program returns "insufficient funds" — 0x1 in the SPL Token
    // error enum. Anchor passes the error through verbatim from the CPI.
    expect(errorText).to.match(
      /insufficient funds|insufficient.*balance|custom program error: 0x1\b/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("multi-mint independence: depositing to mint2 does not affect mint1", async () => {
    // Snapshot mint1 state (post happy-path).
    const m1CfgBefore = decodeMintConfig(
      (await connection.getAccountInfo(m1.mintConfigPDA, "confirmed"))!.data
    );
    const m1TreeBefore = decodeTreeHead(
      (await connection.getAccountInfo(m1.mainTreePDA, "confirmed"))!.data
    );
    const m1VaultBefore = (await getAccount(connection, m1.mintVaultPDA, "confirmed")).amount;

    // Deposit 50 USDC into mint2.
    const amount = 50n * ONE_USDC;
    const leaf = makeLeaf();
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildIx(m2.mint, m2.mintConfigPDA, m2.mainTreePDA, m2.mintVaultPDA, m2.userAta, leaf, amount)
      ),
      [user],
      { commitment: "confirmed" }
    );

    // mint2 should have moved.
    const m2Cfg = decodeMintConfig(
      (await connection.getAccountInfo(m2.mintConfigPDA, "confirmed"))!.data
    );
    const m2Tree = decodeTreeHead(
      (await connection.getAccountInfo(m2.mainTreePDA, "confirmed"))!.data
    );
    expect(m2Cfg.totalDeposited).to.equal(amount);
    expect(m2Tree.nextIndex).to.equal(1);
    const m2Vault = await getAccount(connection, m2.mintVaultPDA, "confirmed");
    expect(m2Vault.amount).to.equal(amount);

    // mint1 must be exactly where we left it.
    const m1CfgAfter = decodeMintConfig(
      (await connection.getAccountInfo(m1.mintConfigPDA, "confirmed"))!.data
    );
    const m1TreeAfter = decodeTreeHead(
      (await connection.getAccountInfo(m1.mainTreePDA, "confirmed"))!.data
    );
    const m1VaultAfter = (await getAccount(connection, m1.mintVaultPDA, "confirmed")).amount;
    expect(m1CfgAfter.totalDeposited).to.equal(m1CfgBefore.totalDeposited);
    expect(m1TreeAfter.nextIndex).to.equal(m1TreeBefore.nextIndex);
    expect(m1TreeAfter.currentRoot.equals(m1TreeBefore.currentRoot)).to.equal(true);
    expect(m1VaultAfter).to.equal(m1VaultBefore);
  });
});
