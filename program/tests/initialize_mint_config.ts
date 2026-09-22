// Raw @solana/web3.js test for initialize_mint_config.
//
// Bypasses the broken `anchor build` / IDL toolchain (anchor-syn 0.30.1
// calls proc_macro2::Span::source_file() which was removed in proc-macro2
// 1.0.86, and the solana-program 1.18 dep tree forbids downgrading).
//
// Constructs the instruction by hand using Anchor's `global:<name>`
// sha256 discriminator pattern. Decodes the resulting MintConfig account
// from raw bytes against the schema in state.rs.
//
// Assumes a fresh solana-test-validator is running on localhost:8899 with
// the darkdrop program loaded at GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU
// (see scripts/run-test.sh — or the README block in this file).

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
import { createMint, TOKEN_PROGRAM_ID } from "@solana/spl-token";

const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const RPC_URL = "http://127.0.0.1:8899";

// Base58 of 32 zero bytes — equals SystemProgram.programId and Pubkey::default() in Rust.
const ZERO_PUBKEY_B58 = "11111111111111111111111111111111";

/** Anchor's `#[program]` discriminator is sha256("global:<name>")[..8]. */
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

describe("initialize_mint_config", function () {
  this.timeout(60_000);

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.generate();
  let mintPubkey: PublicKey;

  // Static PDAs (don't depend on the mint)
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
    // Confirm the validator is up and the program is deployed
    const info = await connection.getAccountInfo(PROGRAM_ID, "confirmed");
    if (!info || !info.executable) {
      throw new Error(
        `Program ${PROGRAM_ID.toBase58()} not deployed at ${RPC_URL}. ` +
          `Start the validator with: solana-test-validator --reset ` +
          `--bpf-program ${PROGRAM_ID.toBase58()} target/deploy/darkdrop.so`
      );
    }

    // Airdrop. 10 SOL is well over the ~0.07 SOL needed for all rent + fees.
    await airdrop(connection, authority.publicKey, 10);

    // Initialize the vault (required for has_one = authority on initialize_mint_config).
    // Account order matches `pub struct InitializeVault` in instructions/initialize.rs.
    const dropCap = 100_000_000_000n; // = MAX_DROP_AMOUNT (state.rs:18)
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
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(initVaultIx),
      [authority],
      { commitment: "confirmed" }
    );

    // Create a fresh SPL mint owned by the test authority.
    mintPubkey = await createMint(
      connection,
      authority,
      authority.publicKey,
      null,
      6
    );
  });

  it("creates a MintConfig PDA with the expected initial state", async () => {
    const [mintConfigPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_config"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );

    // Account order matches `pub struct InitializeMintConfig`.
    const ix = new TransactionInstruction({
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

    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(ix),
      [authority],
      { commitment: "confirmed" }
    );

    // Fetch and decode the resulting account.
    const acc = await connection.getAccountInfo(mintConfigPDA, "confirmed");
    expect(acc, "MintConfig PDA should exist after init").to.not.equal(null);

    const data = acc!.data;
    // 8 disc + 1 bump + 32 mint + 8 reg_at + 32 mt + 32 npt + 32 mv
    //   + 8 td + 8 tw + 1 paused = 162.
    expect(data.length).to.equal(162);

    let off = 8; // skip discriminator
    const bump = data[off]; off += 1;
    const mint = new PublicKey(data.slice(off, off + 32)); off += 32;
    const registeredAt = data.readBigInt64LE(off); off += 8;
    const merkleTree = new PublicKey(data.slice(off, off + 32)); off += 32;
    const notePoolTree = new PublicKey(data.slice(off, off + 32)); off += 32;
    const mintVault = new PublicKey(data.slice(off, off + 32)); off += 32;
    const totalDeposited = data.readBigUInt64LE(off); off += 8;
    const totalWithdrawn = data.readBigUInt64LE(off); off += 8;
    const paused = data[off] === 1; off += 1;

    expect(bump).to.be.greaterThan(0);
    expect(bump).to.be.lessThan(256);
    expect(mint.toBase58()).to.equal(mintPubkey.toBase58());
    expect(registeredAt > 0n).to.equal(true);
    expect(merkleTree.toBase58()).to.equal(ZERO_PUBKEY_B58);
    expect(notePoolTree.toBase58()).to.equal(ZERO_PUBKEY_B58);
    expect(mintVault.toBase58()).to.equal(ZERO_PUBKEY_B58);
    expect(totalDeposited).to.equal(0n);
    expect(totalWithdrawn).to.equal(0n);
    expect(paused).to.equal(false);
  });

  it("fails to initialize the same mint twice (Anchor init constraint)", async () => {
    const [mintConfigPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_config"), mintPubkey.toBuffer()],
      PROGRAM_ID
    );

    const ix = new TransactionInstruction({
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

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(ix),
        [authority],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }

    expect(threw, "second init must throw").to.equal(true);
    // Anchor's `init` constraint creates the PDA via SystemProgram.createAccount.
    // On the second call SystemProgram returns custom error 0x0 ("account
    // already in use"). The exact wording from web3.js varies by version;
    // we accept either the hex code or the human string.
    expect(errorText).to.match(
      /already in use|0x0|custom program error: 0x0/i,
      `got unexpected error text: ${errorText}`
    );
  });
});
