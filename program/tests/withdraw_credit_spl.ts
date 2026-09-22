// Raw @solana/web3.js test for withdraw_credit_spl.
//
// Each test that needs an unconsumed credit note calls `depositAndClaim`
// which:
//   - generates fresh deposit secrets
//   - submits create_drop_spl
//   - updates the JS-side IncrementalMerkleTree mirror
//   - generates a V2 proof at the leaf's index
//   - submits claim_credit_spl
//   - returns the opening (72 bytes: amount || blinding || salt) and the
//     CreditNoteSpl PDA address
//
// The withdraw then consumes the credit note.

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
import {
  createMint,
  createAssociatedTokenAccount,
  mintTo,
  getAccount,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

import {
  initPoseidon,
  poseidonHash,
  nullifierHash as computeNullifierHash,
  amountCommitment as computeAmountCommitment,
  passwordHash as computePasswordHash,
  createLeaf,
  randomFieldElement,
  bigintToBytes32BE,
} from "../../frontend/src/lib/crypto";
import {
  generateClaimProofV2,
  setV2ArtifactPaths,
} from "../../frontend/src/lib/proof";
import { IncrementalMerkleTree } from "../../frontend/src/lib/merkle";

const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const RPC_URL = "http://127.0.0.1:8899";
const DROP_CAP = 100_000_000_000n;
const ONE_USDC = 1_000_000n;

const WASM_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop.wasm";
const ZKEY_V2_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/darkdrop_v2_final.zkey";

function anchorDiscriminator(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function u64LE(n: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n, 0);
  return buf;
}

function u16LE(n: number): Buffer {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(n, 0);
  return buf;
}

function u32LE(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(n, 0);
  return buf;
}

async function airdrop(conn: Connection, to: PublicKey, sol: number): Promise<void> {
  const sig = await conn.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
  await conn.confirmTransaction(sig, "confirmed");
}

interface MintConfig {
  totalWithdrawn: bigint;
}

function decodeMintConfigTotalWithdrawn(data: Buffer): bigint {
  // Layout: disc(8) bump(1) mint(32) registered_at(8) merkle_tree(32) note_pool_tree(32) mint_vault(32)
  //   total_deposited(8) total_withdrawn(8) paused(1)
  return data.readBigUInt64LE(8 + 1 + 32 + 8 + 32 + 32 + 32 + 8);
}

interface MintCtx {
  mint: PublicKey;
  mintConfigPDA: PublicKey;
  mainTreePDA: PublicKey;
  poolTreePDA: PublicKey;
  mintVaultPDA: PublicKey;
  userAta: PublicKey;
  /** JS-side mirror — updated on every deposit so we can build proofs. */
  jsTree: IncrementalMerkleTree;
}

interface ClaimedNote {
  creditNotePDA: PublicKey;
  nullifierPDA: PublicKey;
  nullifierHash: Buffer;
  /** opening bytes ready to pass to withdraw_credit_spl (72 bytes). */
  opening: Buffer;
  recipient: Keypair;
}

describe("withdraw_credit_spl", function () {
  this.timeout(240_000);

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.generate();
  const user = Keypair.generate();
  const payer = Keypair.generate();

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

  let mint1: MintCtx;
  let mint2: MintCtx;
  // Pre-created ATA for payer for mint1 (receives gasless fees).
  let payerAta1: PublicKey;

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

    const userAta = await createAssociatedTokenAccount(connection, authority, mint, user.publicKey);
    await mintTo(connection, authority, mint, userAta, authority, 100_000n * ONE_USDC);

    return {
      mint, mintConfigPDA, mainTreePDA, poolTreePDA, mintVaultPDA, userAta,
      jsTree: new IncrementalMerkleTree(),
    };
  }

  async function depositSpl(m: MintCtx, leaf: Buffer, amount: bigint): Promise<void> {
    await sendAndConfirmTransaction(connection, new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: true },
          { pubkey: m.mintConfigPDA, isSigner: false, isWritable: true },
          { pubkey: m.mainTreePDA, isSigner: false, isWritable: true },
          { pubkey: m.mintVaultPDA, isSigner: false, isWritable: true },
          { pubkey: m.userAta, isSigner: false, isWritable: true },
          { pubkey: m.mint, isSigner: false, isWritable: false },
          { pubkey: user.publicKey, isSigner: true, isWritable: true },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([anchorDiscriminator("create_drop_spl"), leaf, u64LE(amount)]),
      })
    ), [user], { commitment: "confirmed" });
  }

  /** Deposit + claim a fresh credit note. Returns the opening + PDAs. */
  async function depositAndClaim(m: MintCtx, amount: bigint, recipient: Keypair): Promise<ClaimedNote> {
    const secret = randomFieldElement();
    const nullifier = randomFieldElement();
    const blinding = randomFieldElement();
    const password = 0n;
    const leafBig = createLeaf(secret, nullifier, amount, blinding);
    const leafBuf = Buffer.from(bigintToBytes32BE(leafBig));

    await depositSpl(m, leafBuf, amount);
    const leafIndex = m.jsTree.size;
    m.jsTree.insert(leafBig);
    const merkleProof = m.jsTree.getProof(leafIndex);

    const salt = randomFieldElement();
    const nullHash = computeNullifierHash(nullifier);
    const amtCommit = computeAmountCommitment(amount, blinding);
    const pwdHash = computePasswordHash(password);

    const proof = await generateClaimProofV2(
      { secret, nullifier, amount, blindingFactor: blinding, password },
      merkleProof,
      recipient.publicKey,
      nullHash,
      amtCommit,
      pwdHash
    );

    const nullifierHashBuf = Buffer.from(proof.nullifierHash);
    const [nullifierPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_spl"), m.mint.toBuffer(), nullifierHashBuf],
      PROGRAM_ID
    );
    const [creditPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), m.mint.toBuffer(), nullifierHashBuf],
      PROGRAM_ID
    );

    const saltBuf = Buffer.from(bigintToBytes32BE(salt));
    const inputs = Buffer.concat([
      Buffer.from(proof.merkleRoot),
      Buffer.from(proof.amountCommitment),
      Buffer.from(proof.passwordHash),
    ]);
    const claimData = Buffer.concat([
      anchorDiscriminator("claim_credit_spl"),
      nullifierHashBuf,
      Buffer.from(proof.proofA),
      Buffer.from(proof.proofB),
      Buffer.from(proof.proofC),
      u32LE(inputs.length),
      inputs,
      saltBuf,
    ]);

    await sendAndConfirmTransaction(connection, new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: true },
          { pubkey: m.mintConfigPDA, isSigner: false, isWritable: false },
          { pubkey: m.mainTreePDA, isSigner: false, isWritable: false },
          { pubkey: nullifierPDA, isSigner: false, isWritable: true },
          { pubkey: creditPDA, isSigner: false, isWritable: true },
          { pubkey: m.mint, isSigner: false, isWritable: false },
          { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: claimData,
      })
    ), [payer], { commitment: "confirmed" });

    // Opening is 72 bytes (amount || blinding || salt). withdraw_credit_spl
    // tries the on-chain credit.salt first and falls back to this caller salt
    // (Audit 06 M-02).
    const opening = Buffer.concat([
      u64LE(amount),
      Buffer.from(bigintToBytes32BE(blinding)),
      saltBuf,
    ]);

    return { creditNotePDA: creditPDA, nullifierPDA, nullifierHash: nullifierHashBuf, opening, recipient };
  }

  function buildWithdrawIx(args: {
    mintCtx: MintCtx;
    creditNotePDA: PublicKey;
    nullifierHash: Buffer;
    recipientAta: PublicKey;
    payerAta: PublicKey;
    opening: Buffer;
    rate: number;
  }): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: false },
        { pubkey: args.mintCtx.mintConfigPDA, isSigner: false, isWritable: true },
        { pubkey: args.creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: args.mintCtx.mintVaultPDA, isSigner: false, isWritable: true },
        { pubkey: args.recipientAta, isSigner: false, isWritable: true },
        { pubkey: args.payerAta, isSigner: false, isWritable: true },
        { pubkey: args.mintCtx.mint, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("withdraw_credit_spl"),
        args.nullifierHash,
        u32LE(args.opening.length),
        args.opening,
        u16LE(args.rate),
      ]),
    });
  }

  before(async () => {
    const info = await connection.getAccountInfo(PROGRAM_ID, "confirmed");
    if (!info || !info.executable) {
      throw new Error(`Program not deployed at ${RPC_URL}.`);
    }
    await airdrop(connection, authority.publicKey, 100);
    await airdrop(connection, user.publicKey, 5);
    await airdrop(connection, payer.publicKey, 5);

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

    setV2ArtifactPaths(WASM_PATH, ZKEY_V2_PATH);
    await initPoseidon();

    mint1 = await setupMintFoundation();
    mint2 = await setupMintFoundation();

    // Payer ATA for mint1 (the relayer fee destination).
    payerAta1 = await createAssociatedTokenAccount(connection, authority, mint1.mint, payer.publicKey);
  });

  it("happy path: opens commitment, transfers tokens, closes credit note", async () => {
    const recipient = Keypair.generate();
    await airdrop(connection, recipient.publicKey, 1);
    const recipientAta = await createAssociatedTokenAccount(
      connection, authority, mint1.mint, recipient.publicKey
    );

    const amount = 100n * ONE_USDC;
    const note = await depositAndClaim(mint1, amount, recipient);

    const vaultBefore = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;
    const recipientBefore = (await getAccount(connection, recipientAta, "confirmed")).amount;
    const totalWithdrawnBefore = decodeMintConfigTotalWithdrawn(
      (await connection.getAccountInfo(mint1.mintConfigPDA, "confirmed"))!.data
    );
    const payerBalBefore = await connection.getBalance(payer.publicKey, "confirmed");

    await sendAndConfirmTransaction(connection, new Transaction().add(
      buildWithdrawIx({
        mintCtx: mint1,
        creditNotePDA: note.creditNotePDA,
        nullifierHash: note.nullifierHash,
        recipientAta,
        payerAta: payerAta1,
        opening: note.opening,
        rate: 0,
      })
    ), [payer], { commitment: "confirmed" });

    const vaultAfter = (await getAccount(connection, mint1.mintVaultPDA, "confirmed")).amount;
    const recipientAfter = (await getAccount(connection, recipientAta, "confirmed")).amount;
    expect(vaultAfter).to.equal(vaultBefore - amount);
    expect(recipientAfter).to.equal(recipientBefore + amount);

    const totalWithdrawnAfter = decodeMintConfigTotalWithdrawn(
      (await connection.getAccountInfo(mint1.mintConfigPDA, "confirmed"))!.data
    );
    expect(totalWithdrawnAfter).to.equal(totalWithdrawnBefore + amount);

    const noteAcc = await connection.getAccountInfo(note.creditNotePDA, "confirmed");
    expect(noteAcc, "CreditNoteSpl PDA should be closed").to.equal(null);

    const payerBalAfter = await connection.getBalance(payer.publicKey, "confirmed");
    // Payer paid TX fees (~5000 lamports) but got back the credit-note rent
    // (~0.0018 SOL) on close. Net should be positive.
    expect(payerBalAfter).to.be.greaterThan(payerBalBefore - 100_000);
  });

  it("rejects a wrong opening (CommitmentMismatch)", async () => {
    const recipient = Keypair.generate();
    const recipientAta = await createAssociatedTokenAccount(
      connection, authority, mint1.mint, recipient.publicKey
    );
    const amount = 50n * ONE_USDC;
    const note = await depositAndClaim(mint1, amount, recipient);

    // Corrupt the amount (first 8 bytes, little-endian). The amount stays
    // in-field for Poseidon (it's right-padded into a 32-byte big-endian
    // field element on-chain), but the recomputed commitment won't match
    // the stored one. Corrupting the salt instead can push it past the
    // BN254 prime and panic Poseidon — different failure, not what this
    // test wants to exercise.
    const corrupted = Buffer.from(note.opening);
    corrupted[0] ^= 0xff;

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildWithdrawIx({
          mintCtx: mint1,
          creditNotePDA: note.creditNotePDA,
          nullifierHash: note.nullifierHash,
          recipientAta,
          payerAta: payerAta1,
          opening: corrupted,
          rate: 0,
        })
      ), [payer], { commitment: "confirmed" });
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // CommitmentMismatch = errors.rs ordinal 9 → 6009 → 0x1779.
    expect(errorText).to.match(
      /CommitmentMismatch|6009|0x1779/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects replay after a successful withdraw (credit note closed)", async () => {
    const recipient = Keypair.generate();
    const recipientAta = await createAssociatedTokenAccount(
      connection, authority, mint1.mint, recipient.publicKey
    );
    const amount = 25n * ONE_USDC;
    const note = await depositAndClaim(mint1, amount, recipient);

    // First withdraw succeeds.
    await sendAndConfirmTransaction(connection, new Transaction().add(
      buildWithdrawIx({
        mintCtx: mint1,
        creditNotePDA: note.creditNotePDA,
        nullifierHash: note.nullifierHash,
        recipientAta,
        payerAta: payerAta1,
        opening: note.opening,
        rate: 0,
      })
    ), [payer], { commitment: "confirmed" });

    // Replay must fail: credit_note_spl PDA no longer exists.
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildWithdrawIx({
          mintCtx: mint1,
          creditNotePDA: note.creditNotePDA,
          nullifierHash: note.nullifierHash,
          recipientAta,
          payerAta: payerAta1,
          opening: note.opening,
          rate: 0,
        })
      ), [payer], { commitment: "confirmed" });
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // After close, account is gone → AccountNotInitialized (3012/0xbc4) or
    // AccountOwnedByWrongProgram (3007/0xbbf) when re-deserializing.
    expect(errorText).to.match(
      /AccountNotInitialized|AccountOwnedByWrongProgram|3007|3012|0xbbf|0xbc4|not.*initialized|owned by/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects a recipient_ata not owned by credit_note.recipient (UnauthorizedWithdraw)", async () => {
    const recipient = Keypair.generate();
    const decoy = Keypair.generate();
    // Recipient ATA exists for the actual recipient (passes deposit/claim flow).
    await createAssociatedTokenAccount(connection, authority, mint1.mint, recipient.publicKey);
    // But we'll pass the decoy's ATA to the withdraw ix.
    const decoyAta = await createAssociatedTokenAccount(
      connection, authority, mint1.mint, decoy.publicKey
    );

    const amount = 10n * ONE_USDC;
    const note = await depositAndClaim(mint1, amount, recipient);

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildWithdrawIx({
          mintCtx: mint1,
          creditNotePDA: note.creditNotePDA,
          nullifierHash: note.nullifierHash,
          recipientAta: decoyAta,    // <-- wrong owner
          payerAta: payerAta1,
          opening: note.opening,
          rate: 0,
        })
      ), [payer], { commitment: "confirmed" });
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // UnauthorizedWithdraw = errors.rs ordinal 10 → 6010 → 0x177a.
    expect(errorText).to.match(
      /UnauthorizedWithdraw|6010|0x177a/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects using mint2's credit_note against mint1's accounts (cross-mint isolation)", async () => {
    const recipient = Keypair.generate();
    const recipientAtaMint1 = await createAssociatedTokenAccount(
      connection, authority, mint1.mint, recipient.publicKey
    );
    // The credit note is created against mint2's tree/config/etc.
    const amount = 7n * ONE_USDC;
    const note2 = await depositAndClaim(mint2, amount, recipient);

    let threw = false;
    let errorText = "";
    try {
      // mint context = mint1, credit note = mint2's. Seeds for credit_note
      // are [b"credit_spl", mint1, nullifier_hash], which does NOT match
      // note2.creditNotePDA → ConstraintSeeds.
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildWithdrawIx({
          mintCtx: mint1,
          creditNotePDA: note2.creditNotePDA,
          nullifierHash: note2.nullifierHash,
          recipientAta: recipientAtaMint1,
          payerAta: payerAta1,
          opening: note2.opening,
          rate: 0,
        })
      ), [payer], { commitment: "confirmed" });
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    expect(errorText).to.match(
      /ConstraintSeeds|ConstraintHasOne|WrongMint|2001|2006|6024|0x7d1|0x7d6|0x1788/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("gasless mode: rate=100 (1%) splits between recipient and payer", async () => {
    const recipient = Keypair.generate();
    const recipientAta = await createAssociatedTokenAccount(
      connection, authority, mint1.mint, recipient.publicKey
    );
    const amount = 200n * ONE_USDC;
    const note = await depositAndClaim(mint1, amount, recipient);

    const expectedFee = (amount * 100n) / 10000n; // 1%
    const expectedNet = amount - expectedFee;

    const recipientBefore = (await getAccount(connection, recipientAta, "confirmed")).amount;
    const payerAtaBefore = (await getAccount(connection, payerAta1, "confirmed")).amount;

    await sendAndConfirmTransaction(connection, new Transaction().add(
      buildWithdrawIx({
        mintCtx: mint1,
        creditNotePDA: note.creditNotePDA,
        nullifierHash: note.nullifierHash,
        recipientAta,
        payerAta: payerAta1,
        opening: note.opening,
        rate: 100,
      })
    ), [payer], { commitment: "confirmed" });

    const recipientAfter = (await getAccount(connection, recipientAta, "confirmed")).amount;
    const payerAtaAfter = (await getAccount(connection, payerAta1, "confirmed")).amount;

    expect(recipientAfter - recipientBefore).to.equal(expectedNet);
    expect(payerAtaAfter - payerAtaBefore).to.equal(expectedFee);
  });

  // Insufficient-vault-balance test is SKIPPED. Forcing the mint vault
  // below the credit-note amount would require either (a) an admin_sweep_spl
  // ix we haven't built yet, or (b) a test-only direct lamport/token poke
  // that defeats the audit-mirroring discipline. Re-enable once
  // admin_sweep_spl ships.
  it.skip("rejects when mint_vault has insufficient balance (needs admin_sweep_spl)");
});
