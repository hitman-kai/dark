// Raw @solana/web3.js test for initialize_mint_trees. Same approach as
// tests/initialize_mint_config.ts — bypasses the broken IDL toolchain by
// constructing the instruction manually with Anchor's sha256("global:<name>")
// discriminator.

import { expect } from "chai";
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
import { createMint } from "@solana/spl-token";

const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const RPC_URL = "http://127.0.0.1:8899";
const ZERO_PUBKEY_B58 = "11111111111111111111111111111111";

// state.rs:73 — ZERO_HASHES[MERKLE_DEPTH] where MERKLE_DEPTH = 20.
// The Poseidon-hash of an empty depth-20 Merkle tree.
const ZERO_HASH_LEVEL_20 = Buffer.from([
  33, 52, 231, 106, 197, 210, 26, 171, 24, 108, 43, 225, 221, 143, 132, 238,
  136, 10, 30, 70, 234, 247, 18, 249, 211, 113, 182, 223, 34, 25, 31, 62,
]);

// MerkleTreeSpl / NotePoolTreeSpl byte layout (state.rs:408-424, 446-462):
//   discriminator: 8
//   vault:         32   (offset 8)
//   mint:          32   (offset 40)
//   next_index:    u32  (offset 72)
//   root_history_index: u32 (offset 76)
//   current_root:  32   (offset 80)
//   root_history:  256 × 32 = 8192   (offset 112)
//   filled_subtrees: 20 × 32 = 640   (offset 8304)
// Total: 8944 bytes.
const TREE_ACCOUNT_BYTES = 8944;

function anchorDiscriminator(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function u64LE(n: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n, 0);
  return buf;
}

async function airdrop(conn: Connection, to: PublicKey, sol: number): Promise<void> {
  const sig = await conn.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
  await conn.confirmTransaction(sig, "confirmed");
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

describe("initialize_mint_trees", function () {
  this.timeout(60_000);

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.generate();
  let mintPubkey: PublicKey;
  let mintConfigPDA: PublicKey;

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

  before(async () => {
    const info = await connection.getAccountInfo(PROGRAM_ID, "confirmed");
    if (!info || !info.executable) {
      throw new Error(
        `Program ${PROGRAM_ID.toBase58()} not deployed at ${RPC_URL}. ` +
          `Start: solana-test-validator --reset --bpf-program ${PROGRAM_ID.toBase58()} ` +
          `target/deploy/darkdrop.so`
      );
    }

    await airdrop(connection, authority.publicKey, 10);

    // 1. initialize_vault
    const dropCap = 100_000_000_000n;
    const initVaultIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: merkleTreePDA, isSigner: false, isWritable: true },
        { pubkey: treasuryPDA, isSigner: false, isWritable: true },
        { pubkey: authority.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([anchorDiscriminator("initialize_vault"), u64LE(dropCap)]),
    });
    await sendAndConfirmTransaction(connection, new Transaction().add(initVaultIx), [authority], {
      commitment: "confirmed",
    });

    // 2. create test SPL mint
    mintPubkey = await createMint(connection, authority, authority.publicKey, null, 6);

    // 3. initialize_mint_config
    [mintConfigPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_config"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );
    const initCfgIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: mintPubkey, isSigner: false, isWritable: false },
        { pubkey: authority.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: anchorDiscriminator("initialize_mint_config"),
    });
    await sendAndConfirmTransaction(connection, new Transaction().add(initCfgIx), [authority], {
      commitment: "confirmed",
    });
  });

  function buildInitTreesIx(mint: PublicKey, mintConfig: PublicKey, mainTree: PublicKey, poolTree: PublicKey): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfig, isSigner: false, isWritable: true },
        { pubkey: mainTree, isSigner: false, isWritable: true },
        { pubkey: poolTree, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: authority.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: anchorDiscriminator("initialize_mint_trees"),
    });
  }

  it("initializes per-mint main + note pool trees, populates MintConfig refs", async () => {
    const [mainTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree_spl"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );
    const [poolTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_pool_tree_spl"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );

    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildInitTreesIx(mintPubkey, mintConfigPDA, mainTreePDA, poolTreePDA)),
      [authority],
      { commitment: "confirmed" }
    );

    // Main tree assertions
    const mainAcc = await connection.getAccountInfo(mainTreePDA, "confirmed");
    expect(mainAcc, "main tree PDA must exist").to.not.equal(null);
    expect(mainAcc!.data.length).to.equal(TREE_ACCOUNT_BYTES);
    const main = decodeTreeHead(mainAcc!.data);
    expect(main.vault.toBase58()).to.equal(vaultPDA.toBase58());
    expect(main.mint.toBase58()).to.equal(mintPubkey.toBase58());
    expect(main.nextIndex).to.equal(0);
    expect(main.rootHistoryIndex).to.equal(0);
    expect(main.currentRoot.equals(ZERO_HASH_LEVEL_20)).to.equal(true);

    // Pool tree assertions (identical shape)
    const poolAcc = await connection.getAccountInfo(poolTreePDA, "confirmed");
    expect(poolAcc, "pool tree PDA must exist").to.not.equal(null);
    expect(poolAcc!.data.length).to.equal(TREE_ACCOUNT_BYTES);
    const pool = decodeTreeHead(poolAcc!.data);
    expect(pool.vault.toBase58()).to.equal(vaultPDA.toBase58());
    expect(pool.mint.toBase58()).to.equal(mintPubkey.toBase58());
    expect(pool.nextIndex).to.equal(0);
    expect(pool.rootHistoryIndex).to.equal(0);
    expect(pool.currentRoot.equals(ZERO_HASH_LEVEL_20)).to.equal(true);

    // MintConfig should now carry both tree addresses; mint_vault still default.
    const cfgAcc = await connection.getAccountInfo(mintConfigPDA, "confirmed");
    expect(cfgAcc).to.not.equal(null);
    const cfg = decodeMintConfig(cfgAcc!.data);
    expect(cfg.merkleTree.toBase58()).to.equal(mainTreePDA.toBase58());
    expect(cfg.notePoolTree.toBase58()).to.equal(poolTreePDA.toBase58());
    expect(cfg.mintVault.toBase58()).to.equal(ZERO_PUBKEY_B58);
    // Sanity-check the fields the previous instruction set are untouched.
    expect(cfg.mint.toBase58()).to.equal(mintPubkey.toBase58());
    expect(cfg.paused).to.equal(false);
    expect(cfg.totalDeposited).to.equal(0n);
    expect(cfg.totalWithdrawn).to.equal(0n);
  });

  it("fails to initialize trees twice for the same mint (Anchor init constraint)", async () => {
    const [mainTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree_spl"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );
    const [poolTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_pool_tree_spl"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildInitTreesIx(mintPubkey, mintConfigPDA, mainTreePDA, poolTreePDA)),
        [authority],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw, "second init must throw").to.equal(true);
    expect(errorText).to.match(
      /already in use|0x0|custom program error: 0x0/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("fails when mint has not been registered via initialize_mint_config", async () => {
    // Fresh, unregistered mint.
    const mint2 = await createMint(connection, authority, authority.publicKey, null, 6);

    const [mint2ConfigPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_config"), mint2.toBuffer()],
      PROGRAM_ID
    );
    const [main2PDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree_spl"), mint2.toBuffer()],
      PROGRAM_ID
    );
    const [pool2PDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_pool_tree_spl"), mint2.toBuffer()],
      PROGRAM_ID
    );

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildInitTreesIx(mint2, mint2ConfigPDA, main2PDA, pool2PDA)),
        [authority],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw, "init with unregistered mint must throw").to.equal(true);
    // Anchor's `Account<'info, MintConfig>` (no init) fails on a nonexistent
    // PDA with AccountNotInitialized (3012 = 0xbc4) or
    // AccountOwnedByWrongProgram (3007 = 0xbbf), depending on whether
    // Solana materialized the account info.
    expect(errorText).to.match(
      /AccountNotInitialized|AccountOwnedByWrongProgram|3007|3012|0xbbf|0xbc4|not.*initialized|owned by/i,
      `got unexpected error text: ${errorText}`
    );
  });
});
