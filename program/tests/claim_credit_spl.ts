// Raw @solana/web3.js test for claim_credit_spl.
//
// Real Groth16 V2 proofs are generated via the audited frontend helpers
// (imported by relative path). snarkjs and circomlibjs resolve to the
// frontend's node_modules — we don't duplicate those deps into the
// program crate.
//
// Setup: full SPL foundation + a single create_drop_spl deposit. The
// claim then verifies against the per-mint MerkleTreeSpl root.

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
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

// Audited frontend helpers — used verbatim so the proof we generate is
// guaranteed to match the on-chain V2 verifier semantics.
import {
  initPoseidon,
  poseidonHash,
  pubkeyToField,
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

const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const RPC_URL = "http://127.0.0.1:8899";
const DROP_CAP = 100_000_000_000n;
const ONE_USDC = 1_000_000n;
const MERKLE_DEPTH = 20;

// Bundled circuit artifacts — same files the frontend serves.
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

function u32LE(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(n, 0);
  return buf;
}

async function airdrop(conn: Connection, to: PublicKey, sol: number): Promise<void> {
  const sig = await conn.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
  await conn.confirmTransaction(sig, "confirmed");
}

interface CreditNoteSpl {
  bump: number;
  recipient: PublicKey;
  commitment: Buffer;
  nullifierHash: Buffer;
  salt: Buffer;
  createdAt: bigint;
  mint: PublicKey;
}

function decodeCreditNoteSpl(data: Buffer): CreditNoteSpl {
  let off = 8;
  const bump = data[off]; off += 1;
  const recipient = new PublicKey(data.slice(off, off + 32)); off += 32;
  const commitment = data.slice(off, off + 32); off += 32;
  const nullifierHashB = data.slice(off, off + 32); off += 32;
  const salt = data.slice(off, off + 32); off += 32;
  const createdAt = data.readBigInt64LE(off); off += 8;
  const mint = new PublicKey(data.slice(off, off + 32));
  return { bump, recipient, commitment, nullifierHash: nullifierHashB, salt, createdAt, mint };
}

interface VaultState { totalDrops: bigint; totalClaims: bigint; }

function decodeVault(data: Buffer): VaultState {
  // Layout: disc(8) + bump(1) + authority(32) + total_drops(8) + total_claims(8) + drop_cap(8) + merkle_tree(32) + total_deposited(8) + total_withdrawn(8)
  return {
    totalDrops: data.readBigUInt64LE(8 + 1 + 32),
    totalClaims: data.readBigUInt64LE(8 + 1 + 32 + 8),
  };
}

/** Build a merkle proof for a leaf at `index` in a tree that had exactly
 *  one insertion (the leaf itself, at position 0). For a single-leaf tree
 *  at index 0, all siblings on the path are zero-subtree hashes and all
 *  indices are 0. */
function buildSingleLeafProof(root: bigint): { pathElements: bigint[]; pathIndices: number[]; root: bigint } {
  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];
  let zero = 0n;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    pathElements.push(zero);
    pathIndices.push(0);
    zero = poseidonHash([zero, zero]);
  }
  return { pathElements, pathIndices, root };
}

/** Compose the current root from a single leaf insertion at index 0
 *  (mirrors merkle_tree_append for the single-leaf case). */
function rootForSingleLeaf(leaf: bigint): bigint {
  let h = leaf;
  let zero = 0n;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    h = poseidonHash([h, zero]);
    zero = poseidonHash([zero, zero]);
  }
  return h;
}

describe("claim_credit_spl", function () {
  this.timeout(180_000);

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.generate();
  const user = Keypair.generate();
  const payer = Keypair.generate();
  const recipient = Keypair.generate();

  const [vaultPDA] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
  const [merkleTreePDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vaultPDA.toBuffer()],
    PROGRAM_ID
  );
  const [treasuryPDA] = PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID);

  // Mint 1 (claim happens against this one)
  let mint1: PublicKey;
  let mint1ConfigPDA: PublicKey;
  let mint1MainTreePDA: PublicKey;
  let mint1PoolTreePDA: PublicKey;
  let mint1VaultPDA: PublicKey;
  let mint1UserAta: PublicKey;

  // Mint 2 (used only for the wrong-mint-isolation test)
  let mint2: PublicKey;
  let mint2ConfigPDA: PublicKey;
  let mint2MainTreePDA: PublicKey;

  // Captured deposit secrets and the generated V2 proof.
  let secret: bigint;
  let nullifier: bigint;
  let amount: bigint;
  let blinding: bigint;
  let password: bigint;
  let nullHash: bigint;
  let amtCommit: bigint;
  let pwdHash: bigint;
  let salt: bigint;
  let merkleRoot: bigint;
  let proof: Awaited<ReturnType<typeof generateClaimProofV2>>;

  // PDAs derived from the deposit's nullifier_hash.
  let nullifierSplPDA: PublicKey;
  let creditNoteSplPDA: PublicKey;

  // Common ix build helper.
  function buildClaimIx(args: {
    mint: PublicKey;
    mintConfig: PublicKey;
    mainTree: PublicKey;
    nullifierPda: PublicKey;
    creditPda: PublicKey;
    recipient: PublicKey;
    nullifierHash: Buffer;
    proofA: Uint8Array;
    proofB: Uint8Array;
    proofC: Uint8Array;
    inputs: Buffer;
    salt: Buffer;
  }): TransactionInstruction {
    const data = Buffer.concat([
      anchorDiscriminator("claim_credit_spl"),
      args.nullifierHash,
      Buffer.from(args.proofA),
      Buffer.from(args.proofB),
      Buffer.from(args.proofC),
      u32LE(args.inputs.length),
      args.inputs,
      args.salt,
    ]);
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: args.mintConfig, isSigner: false, isWritable: false },
        { pubkey: args.mainTree, isSigner: false, isWritable: false },
        { pubkey: args.nullifierPda, isSigner: false, isWritable: true },
        { pubkey: args.creditPda, isSigner: false, isWritable: true },
        { pubkey: args.mint, isSigner: false, isWritable: false },
        { pubkey: args.recipient, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
  }

  // Foundation chain for a single mint (config + trees + vault).
  async function setupMintFoundation(mint: PublicKey): Promise<{
    mintConfigPDA: PublicKey;
    mainTreePDA: PublicKey;
    poolTreePDA: PublicKey;
    mintVaultPDA: PublicKey;
  }> {
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

    return { mintConfigPDA, mainTreePDA, poolTreePDA, mintVaultPDA };
  }

  before(async () => {
    const info = await connection.getAccountInfo(PROGRAM_ID, "confirmed");
    if (!info || !info.executable) {
      throw new Error(`Program not deployed at ${RPC_URL}.`);
    }
    await airdrop(connection, authority.publicKey, 50);
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

    // mint1 foundation + user balance
    mint1 = await createMint(connection, authority, authority.publicKey, null, 6);
    ({
      mintConfigPDA: mint1ConfigPDA,
      mainTreePDA: mint1MainTreePDA,
      poolTreePDA: mint1PoolTreePDA,
      mintVaultPDA: mint1VaultPDA,
    } = await setupMintFoundation(mint1));
    mint1UserAta = await createAssociatedTokenAccount(connection, authority, mint1, user.publicKey);
    await mintTo(connection, authority, mint1, mint1UserAta, authority, 10_000n * ONE_USDC);

    // mint2 foundation (no user balance needed — used only for cross-mint test)
    mint2 = await createMint(connection, authority, authority.publicKey, null, 6);
    ({ mintConfigPDA: mint2ConfigPDA, mainTreePDA: mint2MainTreePDA } = await setupMintFoundation(mint2));

    // Bind frontend proof helpers to our local artifact files.
    setV2ArtifactPaths(WASM_PATH, ZKEY_V2_PATH);
    await initPoseidon();

    // Generate deposit secrets and the leaf.
    secret = randomFieldElement();
    nullifier = randomFieldElement();
    blinding = randomFieldElement();
    amount = 100n * ONE_USDC;
    password = 0n;

    nullHash = computeNullifierHash(nullifier);
    amtCommit = computeAmountCommitment(amount, blinding);
    pwdHash = computePasswordHash(password);
    const leaf = createLeaf(secret, nullifier, amount, blinding);

    // Deposit the leaf via create_drop_spl into mint1's tree.
    const leafBuf = Buffer.from(bigintToBytes32BE(leaf));
    await sendAndConfirmTransaction(connection, new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAM_ID,
        keys: [
          { pubkey: vaultPDA, isSigner: false, isWritable: true },
          { pubkey: mint1ConfigPDA, isSigner: false, isWritable: true },
          { pubkey: mint1MainTreePDA, isSigner: false, isWritable: true },
          { pubkey: mint1VaultPDA, isSigner: false, isWritable: true },
          { pubkey: mint1UserAta, isSigner: false, isWritable: true },
          { pubkey: mint1, isSigner: false, isWritable: false },
          { pubkey: user.publicKey, isSigner: true, isWritable: true },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([
          anchorDiscriminator("create_drop_spl"),
          leafBuf,
          u64LE(amount),
        ]),
      })
    ), [user], { commitment: "confirmed" });

    // Compute the post-insertion root using the same algorithm the program
    // ran. We deposited as the first (and only) leaf at index 0.
    merkleRoot = rootForSingleLeaf(leaf);
    const merkleProof = buildSingleLeafProof(merkleRoot);

    // Random salt for the M-01-NEW commitment re-randomization.
    salt = randomFieldElement();

    // Generate the V2 proof. This is the slow part (snarkjs ~1-3s).
    proof = await generateClaimProofV2(
      { secret, nullifier, amount, blindingFactor: blinding, password },
      merkleProof,
      recipient.publicKey,
      nullHash,
      amtCommit,
      pwdHash
    );

    [nullifierSplPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_spl"), mint1.toBuffer(), proof.nullifierHash],
      PROGRAM_ID
    );
    [creditNoteSplPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), mint1.toBuffer(), proof.nullifierHash],
      PROGRAM_ID
    );
  });

  it("happy path: verifies V2 proof, creates nullifier + credit note, bumps total_claims", async () => {
    const vaultBefore = decodeVault((await connection.getAccountInfo(vaultPDA, "confirmed"))!.data);

    const inputs = Buffer.concat([
      Buffer.from(proof.merkleRoot),
      Buffer.from(proof.amountCommitment),
      Buffer.from(proof.passwordHash),
    ]);

    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildClaimIx({
          mint: mint1,
          mintConfig: mint1ConfigPDA,
          mainTree: mint1MainTreePDA,
          nullifierPda: nullifierSplPDA,
          creditPda: creditNoteSplPDA,
          recipient: recipient.publicKey,
          nullifierHash: Buffer.from(proof.nullifierHash),
          proofA: proof.proofA,
          proofB: proof.proofB,
          proofC: proof.proofC,
          inputs,
          salt: Buffer.from(bigintToBytes32BE(salt)),
        })
      ),
      [payer],
      { commitment: "confirmed" }
    );

    // Nullifier PDA exists.
    const nAcc = await connection.getAccountInfo(nullifierSplPDA, "confirmed");
    expect(nAcc, "nullifier PDA should exist").to.not.equal(null);
    expect(nAcc!.data.length).to.equal(8 + 32);

    // CreditNoteSpl exists with the expected fields.
    const cAcc = await connection.getAccountInfo(creditNoteSplPDA, "confirmed");
    expect(cAcc, "credit note PDA should exist").to.not.equal(null);
    const credit = decodeCreditNoteSpl(cAcc!.data);
    expect(credit.recipient.toBase58()).to.equal(recipient.publicKey.toBase58());
    expect(credit.mint.toBase58()).to.equal(mint1.toBase58());
    expect(credit.nullifierHash.equals(Buffer.from(proof.nullifierHash))).to.equal(true);
    expect(credit.salt.equals(Buffer.from(bigintToBytes32BE(salt)))).to.equal(true);
    expect(credit.createdAt > 0n).to.equal(true);

    // Stored commitment = Poseidon(amount_commitment, salt) — re-randomized.
    const expectedStored = poseidonHash([amtCommit, salt]);
    expect(credit.commitment.equals(Buffer.from(bigintToBytes32BE(expectedStored)))).to.equal(true);

    // total_claims incremented.
    const vaultAfter = decodeVault((await connection.getAccountInfo(vaultPDA, "confirmed"))!.data);
    expect(vaultAfter.totalClaims).to.equal(vaultBefore.totalClaims + 1n);
  });

  it("rejects double-claim with the same nullifier (Anchor init constraint)", async () => {
    const inputs = Buffer.concat([
      Buffer.from(proof.merkleRoot),
      Buffer.from(proof.amountCommitment),
      Buffer.from(proof.passwordHash),
    ]);
    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildClaimIx({
            mint: mint1,
            mintConfig: mint1ConfigPDA,
            mainTree: mint1MainTreePDA,
            nullifierPda: nullifierSplPDA,
            creditPda: creditNoteSplPDA,
            recipient: recipient.publicKey,
            nullifierHash: Buffer.from(proof.nullifierHash),
            proofA: proof.proofA,
            proofB: proof.proofB,
            proofC: proof.proofC,
            inputs,
            salt: Buffer.from(bigintToBytes32BE(salt)),
          })
        ),
        [payer],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    expect(errorText).to.match(
      /already in use|0x0|custom program error: 0x0/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects an invalid (corrupted) proof", async () => {
    // Fresh nullifier so we get past the init check and into the verifier.
    const freshNullifier = randomFieldElement();
    const freshHash = computeNullifierHash(freshNullifier);
    const freshHashBuf = Buffer.from(bigintToBytes32BE(freshHash));

    // We can't easily forge a different valid proof, but we can mint a
    // brand-new (secret, nullifier) and rebuild a leaf+root, then corrupt
    // proof_a so the verifier rejects. The merkle root passes is_known_root
    // because we'll re-use the post-deposit root — but the proof bytes don't
    // match anything valid. Verifier returns InvalidProof.
    const corruptedProofA = new Uint8Array(proof.proofA);
    corruptedProofA[0] ^= 0xff;

    const [n2] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_spl"), mint1.toBuffer(), freshHashBuf],
      PROGRAM_ID
    );
    const [c2] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), mint1.toBuffer(), freshHashBuf],
      PROGRAM_ID
    );

    const inputs = Buffer.concat([
      Buffer.from(proof.merkleRoot),
      Buffer.from(proof.amountCommitment),
      Buffer.from(proof.passwordHash),
    ]);

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildClaimIx({
            mint: mint1,
            mintConfig: mint1ConfigPDA,
            mainTree: mint1MainTreePDA,
            nullifierPda: n2,
            creditPda: c2,
            recipient: recipient.publicKey,
            nullifierHash: freshHashBuf,
            proofA: corruptedProofA,
            proofB: proof.proofB,
            proofC: proof.proofC,
            inputs,
            salt: Buffer.from(bigintToBytes32BE(salt)),
          })
        ),
        [payer],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // InvalidProof = errors.rs ordinal 3 → 6003 → 0x1773.
    // Some corrupted G1/G2 inputs cause the verifier to reject before the
    // pairing check returns — either way the program maps it to InvalidProof.
    expect(errorText).to.match(
      /InvalidProof|6003|0x1773/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects a stale / unknown merkle_root (InvalidRoot)", async () => {
    // Use a fresh nullifier so the init check passes; pass garbage as the
    // merkle_root in inputs. The is_known_root check fires before the
    // verifier runs.
    const freshNullifier = randomFieldElement();
    const freshHash = computeNullifierHash(freshNullifier);
    const freshHashBuf = Buffer.from(bigintToBytes32BE(freshHash));

    const [n3] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_spl"), mint1.toBuffer(), freshHashBuf],
      PROGRAM_ID
    );
    const [c3] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), mint1.toBuffer(), freshHashBuf],
      PROGRAM_ID
    );

    // Field-valid 32-byte root that the SPL tree has never seen.
    const phonyRoot = Buffer.alloc(32);
    phonyRoot[31] = 0xab; // tiny number, not on chain

    const inputs = Buffer.concat([
      phonyRoot,
      Buffer.from(proof.amountCommitment),
      Buffer.from(proof.passwordHash),
    ]);

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildClaimIx({
            mint: mint1,
            mintConfig: mint1ConfigPDA,
            mainTree: mint1MainTreePDA,
            nullifierPda: n3,
            creditPda: c3,
            recipient: recipient.publicKey,
            nullifierHash: freshHashBuf,
            proofA: proof.proofA,
            proofB: proof.proofB,
            proofC: proof.proofC,
            inputs,
            salt: Buffer.from(bigintToBytes32BE(salt)),
          })
        ),
        [payer],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // InvalidRoot = errors.rs ordinal 1 → 6001 → 0x1771.
    expect(errorText).to.match(
      /InvalidRoot|6001|0x1771/i,
      `got unexpected error text: ${errorText}`
    );
  });

  it("rejects a mint↔mint_config mismatch (cross-mint isolation)", async () => {
    // Fresh nullifier to clear the init check. Pass mint1's everything
    // EXCEPT pass mint2's mint_config — mint_config's seeds (derived from
    // mint=mint1) won't match mint2ConfigPDA.
    const freshNullifier = randomFieldElement();
    const freshHash = computeNullifierHash(freshNullifier);
    const freshHashBuf = Buffer.from(bigintToBytes32BE(freshHash));

    const [n4] = PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier_spl"), mint1.toBuffer(), freshHashBuf],
      PROGRAM_ID
    );
    const [c4] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), mint1.toBuffer(), freshHashBuf],
      PROGRAM_ID
    );

    const inputs = Buffer.concat([
      Buffer.from(proof.merkleRoot),
      Buffer.from(proof.amountCommitment),
      Buffer.from(proof.passwordHash),
    ]);

    let threw = false;
    let errorText = "";
    try {
      await sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildClaimIx({
            mint: mint1,
            mintConfig: mint2ConfigPDA,    // <-- the bad one
            mainTree: mint1MainTreePDA,
            nullifierPda: n4,
            creditPda: c4,
            recipient: recipient.publicKey,
            nullifierHash: freshHashBuf,
            proofA: proof.proofA,
            proofB: proof.proofB,
            proofC: proof.proofC,
            inputs,
            salt: Buffer.from(bigintToBytes32BE(salt)),
          })
        ),
        [payer],
        { commitment: "confirmed" }
      );
    } catch (e: any) {
      threw = true;
      errorText = String(e?.message ?? e);
    }
    expect(threw).to.equal(true);
    // Anchor checks either seeds (ConstraintSeeds=2006/0x7d6) or has_one
    // (ConstraintHasOne=2001/0x7d1) — both indicate the right kind of failure.
    expect(errorText).to.match(
      /ConstraintSeeds|ConstraintHasOne|2001|2006|0x7d1|0x7d6/i,
      `got unexpected error text: ${errorText}`
    );
  });
});
