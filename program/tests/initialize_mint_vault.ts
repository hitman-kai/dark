// Raw @solana/web3.js test for initialize_mint_vault. Same approach as the
// other foundation tests — manual instruction construction, no IDL.

import { expect } from "chai";
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
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { createMint, getAccount, TOKEN_PROGRAM_ID } from "@solana/spl-token";

const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const RPC_URL = "http://127.0.0.1:8899";
const ZERO_PUBKEY_B58 = "11111111111111111111111111111111";

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

describe("initialize_mint_vault", function () {
  this.timeout(60_000);

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.generate();
  let mintPubkey: PublicKey;
  let mintConfigPDA: PublicKey;
  let mintVaultPDA: PublicKey;

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

  /** Build a fully-validated initialize_mint_vault instruction. */
  function buildInitVaultIx(
    mint: PublicKey,
    mintConfig: PublicKey,
    mintVault: PublicKey
  ): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfig, isSigner: false, isWritable: true },
        { pubkey: mintVault, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: authority.publicKey, isSigner: true, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
      ],
      data: anchorDiscriminator("initialize_mint_vault"),
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

    // 2. create test mint
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

    // 4. initialize_mint_trees
    const [mainTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree_spl"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );
    const [poolTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_pool_tree_spl"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );
    const initTreesIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: mainTreePDA, isSigner: false, isWritable: true },
        { pubkey: poolTreePDA, isSigner: false, isWritable: true },
        { pubkey: mintPubkey, isSigner: false, isWritable: false },
        { pubkey: authority.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: anchorDiscriminator("initialize_mint_trees"),
    });
    await sendAndConfirmTransaction(connection, new Transaction().add(initTreesIx), [authority], {
      commitment: "confirmed",
    });

    // PDA for the mint vault we'll be testing
    [mintVaultPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_vault"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );
  });

  it("creates the program-owned token vault and links it on MintConfig", async () => {
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(buildInitVaultIx(mintPubkey, mintConfigPDA, mintVaultPDA)),
      [authority],
      { commitment: "confirmed" }
    );

    // Decode the token account via @solana/spl-token's helper.
    const tokenAcc = await getAccount(connection, mintVaultPDA, "confirmed", TOKEN_PROGRAM_ID);
    expect(tokenAcc.mint.toBase58()).to.equal(mintPubkey.toBase58());
    expect(tokenAcc.owner.toBase58()).to.equal(vaultPDA.toBase58());
    expect(tokenAcc.amount).to.equal(0n);

    // MintConfig should now have mint_vault populated.
    const cfgAcc = await connection.getAccountInfo(mintConfigPDA, "confirmed");
    expect(cfgAcc).to.not.equal(null);
    const cfg = decodeMintConfig(cfgAcc!.data);
    expect(cfg.mintVault.toBase58()).to.equal(mintVaultPDA.toBase58());
    // The two earlier-set fields are still correct.
    expect(cfg.merkleTree.toBase58()).to.not.equal(ZERO_PUBKEY_B58);
    expect(cfg.notePoolTree.toBase58()).to.not.equal(ZERO_PUBKEY_B58);
    expect(cfg.mint.toBase58()).to.equal(mintPubkey.toBase58());
  });

  it("fails to initialize the mint vault twice (Anchor init constraint)", async () => {
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildInitVaultIx(mintPubkey, mintConfigPDA, mintVaultPDA)),
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

  it("fails when trees have not been initialized for the mint (MintNotRegistered)", async () => {
    // mint2: registered (mint_config exists) but trees were never set up.
    const mint2 = await createMint(connection, authority, authority.publicKey, null, 6);

    const [mint2ConfigPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_config"), mint2.toBuffer()],
      PROGRAM_ID
    );
    const [mint2VaultPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_vault"), mint2.toBuffer()],
      PROGRAM_ID
    );

    // Call initialize_mint_config but skip initialize_mint_trees.
    const initCfgIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: mint2ConfigPDA, isSigner: false, isWritable: true },
        { pubkey: mint2, isSigner: false, isWritable: false },
        { pubkey: authority.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: anchorDiscriminator("initialize_mint_config"),
    });
    await sendAndConfirmTransaction(connection, new Transaction().add(initCfgIx), [authority], {
      commitment: "confirmed",
    });

    // Now try initialize_mint_vault — must fail at the require! checks.
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(buildInitVaultIx(mint2, mint2ConfigPDA, mint2VaultPDA)),
        [authority],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw, "init without trees must throw").to.equal(true);
    // MintNotRegistered = error code 6022 = 0x1786 (errors.rs ordinal).
    // Anchor prints it as "Error Code: MintNotRegistered. Error Number: 6022."
    expect(errorText).to.match(
      /MintNotRegistered|6022|0x1786/i,
      `got unexpected error text: ${errorText}`
    );
  });
});
