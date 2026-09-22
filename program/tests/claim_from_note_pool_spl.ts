// Raw @solana/web3.js test for claim_from_note_pool_spl.
//
// Pool V3 proofs come from the audited frontend helper
// `generateClaimProofV3`. snarkjs / circomlibjs resolve to
// frontend/node_modules via the relative import.
//
// Per-test flow: fresh pool deposit (create_drop_to_pool_spl) → V3 proof
// → claim_from_note_pool_spl. Each successful claim consumes a unique
// pool nullifier, so the negative tests use a SEPARATE pool deposit
// from the happy-path one.

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

import {
  initPoseidon,
  poseidonHash,
  nullifierHash as computeNullifierHash,
  randomFieldElement,
  bigintToBytes32BE,
} from "../../frontend/src/lib/crypto";
import {
  generateClaimProofV3,
  setV3ArtifactPaths,
} from "../../frontend/src/lib/proof";
import { IncrementalMerkleTree } from "../../frontend/src/lib/merkle";

const PROGRAM_ID = new PublicKey("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");
const RPC_URL = "http://127.0.0.1:8899";
const DROP_CAP = 100_000_000_000n;
const ONE_USDC = 1_000_000n;

const WASM_V3_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/note_pool.wasm";
const ZKEY_V3_PATH = "/mnt/d/darkdrop-v4/frontend/public/circuits/note_pool_final.zkey";

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

/** u64 → 32-byte big-endian — matches the on-chain encoding used by
 *  create_drop_to_pool_spl to construct the pool leaf. */
function u64BE32(n: bigint): bigint {
  return n; // Poseidon input is just the integer; on-chain conversion is BE-padding to 32 bytes which Poseidon ingests as the integer.
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

function decodeVaultTotalClaims(data: Buffer): bigint {
  return data.readBigUInt64LE(8 + 1 + 32 + 8);
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
  /** JS-side mirror of the per-mint pool tree, updated on every deposit. */
  poolTree: IncrementalMerkleTree;
}

describe("claim_from_note_pool_spl", function () {
  this.timeout(240_000);

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = Keypair.generate();
  const user = Keypair.generate();
  const payer = Keypair.generate();

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
      [Buffer.from("mint_config"), mint.toBuffer()], PROGRAM_ID);
    const [mainTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree_spl"), mint.toBuffer()], PROGRAM_ID);
    const [poolTreePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("note_pool_tree_spl"), mint.toBuffer()], PROGRAM_ID);
    const [mintVaultPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint_vault"), mint.toBuffer()], PROGRAM_ID);

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

    return { mint, mintConfigPDA, mainTreePDA, poolTreePDA, mintVaultPDA, userAta,
             poolTree: new IncrementalMerkleTree() };
  }

  async function poolDeposit(m: MintCtx, amount: bigint): Promise<{
    poolSecret: bigint;
    poolNullifier: bigint;
    poolBlinding: bigint;
    amount: bigint;
    leafIndex: number;
  }> {
    const poolSecret = randomFieldElement();
    const poolNullifier = randomFieldElement();
    const poolBlinding = randomFieldElement();

    // pool_leaf = Poseidon(poolSecret, poolNullifier, amount, poolBlinding) — matches
    // create_drop_to_pool_spl's on-chain construction.
    const leaf = poseidonHash([poolSecret, poolNullifier, amount, poolBlinding]);

    const params = Buffer.concat([
      Buffer.from(bigintToBytes32BE(poolSecret)),
      Buffer.from(bigintToBytes32BE(poolNullifier)),
      Buffer.from(bigintToBytes32BE(poolBlinding)),
    ]);

    await sendAndConfirmTransaction(connection, new Transaction().add(
      new TransactionInstruction({
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
      })
    ), [user], { commitment: "confirmed" });

    const leafIndex = m.poolTree.size;
    m.poolTree.insert(leaf);

    return { poolSecret, poolNullifier, poolBlinding, amount, leafIndex };
  }

  async function makePoolClaimProof(args: {
    m: MintCtx;
    secrets: Awaited<ReturnType<typeof poolDeposit>>;
    recipient: Keypair;
  }): Promise<{
    proof: Awaited<ReturnType<typeof generateClaimProofV3>>;
    poolNullifierHashBuf: Buffer;
  }> {
    const merkleProof = args.m.poolTree.getProof(args.secrets.leafIndex);
    const poolNullifierHash = computeNullifierHash(args.secrets.poolNullifier);
    const newBlinding = randomFieldElement();
    const newSalt = randomFieldElement();

    const proof = await generateClaimProofV3(
      {
        poolSecret: args.secrets.poolSecret,
        poolNullifier: args.secrets.poolNullifier,
        poolBlinding: args.secrets.poolBlinding,
        amount: args.secrets.amount,
      },
      merkleProof,
      args.recipient.publicKey,
      poolNullifierHash,
      newBlinding,
      newSalt
    );

    return { proof, poolNullifierHashBuf: Buffer.from(proof.poolNullifierHash) };
  }

  function buildClaimIx(args: {
    m: MintCtx;
    poolNullifierPDA: PublicKey;
    creditNotePDA: PublicKey;
    recipient: PublicKey;
    poolNullifierHash: Buffer;
    proofA: Uint8Array;
    proofB: Uint8Array;
    proofC: Uint8Array;
    inputs: Buffer;
  }): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: args.m.mintConfigPDA, isSigner: false, isWritable: false },
        { pubkey: args.m.poolTreePDA, isSigner: false, isWritable: false },
        { pubkey: args.poolNullifierPDA, isSigner: false, isWritable: true },
        { pubkey: args.creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: args.m.mint, isSigner: false, isWritable: false },
        { pubkey: args.recipient, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("claim_from_note_pool_spl"),
        args.poolNullifierHash,
        Buffer.from(args.proofA),
        Buffer.from(args.proofB),
        Buffer.from(args.proofC),
        u32LE(args.inputs.length),
        args.inputs,
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
    await airdrop(connection, payer.publicKey, 5);

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

    setV3ArtifactPaths(WASM_V3_PATH, ZKEY_V3_PATH);
    await initPoseidon();

    mint1 = await setupMintFoundation(10_000n * ONE_USDC);
    mint2 = await setupMintFoundation(1_000n * ONE_USDC);
  });

  it("happy path: V3 proof verifies, pool nullifier + credit note created, tree unchanged", async () => {
    const recipient = Keypair.generate();
    const secrets = await poolDeposit(mint1, 100n * ONE_USDC);

    const poolTreeBefore = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.poolTreePDA, "confirmed"))!.data
    );
    const totalClaimsBefore = decodeVaultTotalClaims(
      (await connection.getAccountInfo(vaultPDA, "confirmed"))!.data
    );

    const { proof, poolNullifierHashBuf } = await makePoolClaimProof({
      m: mint1, secrets, recipient,
    });

    const [poolNullifierPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool_nullifier_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );
    const [creditNotePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );

    const inputs = Buffer.concat([
      Buffer.from(proof.poolMerkleRoot),
      Buffer.from(proof.newStoredCommitment),
    ]);

    await sendAndConfirmTransaction(connection, new Transaction().add(
      buildClaimIx({
        m: mint1,
        poolNullifierPDA,
        creditNotePDA,
        recipient: recipient.publicKey,
        poolNullifierHash: poolNullifierHashBuf,
        proofA: proof.proofA,
        proofB: proof.proofB,
        proofC: proof.proofC,
        inputs,
      })
    ), [payer], { commitment: "confirmed" });

    // PoolNullifierAccountSpl exists.
    const nAcc = await connection.getAccountInfo(poolNullifierPDA, "confirmed");
    expect(nAcc, "pool nullifier PDA should exist").to.not.equal(null);

    // CreditNoteSpl populated correctly.
    const cAcc = await connection.getAccountInfo(creditNotePDA, "confirmed");
    expect(cAcc, "credit note should exist").to.not.equal(null);
    const credit = decodeCreditNoteSpl(cAcc!.data);
    expect(credit.recipient.toBase58()).to.equal(recipient.publicKey.toBase58());
    expect(credit.mint.toBase58()).to.equal(mint1.mint.toBase58());
    expect(credit.nullifierHash.equals(poolNullifierHashBuf)).to.equal(true);
    expect(credit.commitment.equals(Buffer.from(proof.newStoredCommitment))).to.equal(true);
    // Cosmetic salt should be Poseidon(pool_nullifier_hash, new_stored_commitment).
    const expectedSalt = poseidonHash([
      BigInt("0x" + poolNullifierHashBuf.toString("hex")),
      BigInt("0x" + Buffer.from(proof.newStoredCommitment).toString("hex")),
    ]);
    expect(credit.salt.equals(Buffer.from(bigintToBytes32BE(expectedSalt)))).to.equal(true);

    // total_claims bumped.
    const totalClaimsAfter = decodeVaultTotalClaims(
      (await connection.getAccountInfo(vaultPDA, "confirmed"))!.data
    );
    expect(totalClaimsAfter).to.equal(totalClaimsBefore + 1n);

    // Pool tree unchanged (claim doesn't modify the tree).
    const poolTreeAfter = decodeTreeNextIndex(
      (await connection.getAccountInfo(mint1.poolTreePDA, "confirmed"))!.data
    );
    expect(poolTreeAfter).to.equal(poolTreeBefore);
  });

  it("rejects double-claim with the same pool_nullifier_hash", async () => {
    const recipient = Keypair.generate();
    const secrets = await poolDeposit(mint1, 50n * ONE_USDC);
    const { proof, poolNullifierHashBuf } = await makePoolClaimProof({
      m: mint1, secrets, recipient,
    });

    const [poolNullifierPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool_nullifier_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );
    const [creditNotePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );
    const inputs = Buffer.concat([
      Buffer.from(proof.poolMerkleRoot),
      Buffer.from(proof.newStoredCommitment),
    ]);

    // First claim succeeds.
    await sendAndConfirmTransaction(connection, new Transaction().add(
      buildClaimIx({
        m: mint1, poolNullifierPDA, creditNotePDA, recipient: recipient.publicKey,
        poolNullifierHash: poolNullifierHashBuf,
        proofA: proof.proofA, proofB: proof.proofB, proofC: proof.proofC, inputs,
      })
    ), [payer], { commitment: "confirmed" });

    // Replay fails — Anchor init on the pool nullifier PDA.
    let threw = false; let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildClaimIx({
          m: mint1, poolNullifierPDA, creditNotePDA, recipient: recipient.publicKey,
          poolNullifierHash: poolNullifierHashBuf,
          proofA: proof.proofA, proofB: proof.proofB, proofC: proof.proofC, inputs,
        })
      ), [payer], { commitment: "confirmed" });
    } catch (e: any) { threw = true; errorText = String(e?.message ?? e); }
    expect(threw).to.equal(true);
    expect(errorText).to.match(/already in use|0x0|custom program error: 0x0/i,
      `got unexpected error text: ${errorText}`);
  });

  it("rejects a corrupted proof (InvalidProof)", async () => {
    const recipient = Keypair.generate();
    const secrets = await poolDeposit(mint1, 30n * ONE_USDC);
    const { proof, poolNullifierHashBuf } = await makePoolClaimProof({
      m: mint1, secrets, recipient,
    });

    const corruptedProofA = new Uint8Array(proof.proofA);
    corruptedProofA[0] ^= 0xff;

    const [poolNullifierPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool_nullifier_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );
    const [creditNotePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );
    const inputs = Buffer.concat([
      Buffer.from(proof.poolMerkleRoot),
      Buffer.from(proof.newStoredCommitment),
    ]);

    let threw = false; let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildClaimIx({
          m: mint1, poolNullifierPDA, creditNotePDA, recipient: recipient.publicKey,
          poolNullifierHash: poolNullifierHashBuf,
          proofA: corruptedProofA, proofB: proof.proofB, proofC: proof.proofC, inputs,
        })
      ), [payer], { commitment: "confirmed" });
    } catch (e: any) { threw = true; errorText = String(e?.message ?? e); }
    expect(threw).to.equal(true);
    expect(errorText).to.match(/InvalidProof|6003|0x1773/i,
      `got unexpected error text: ${errorText}`);
  });

  it("rejects an unknown pool merkle root (InvalidRoot)", async () => {
    const recipient = Keypair.generate();
    const secrets = await poolDeposit(mint1, 25n * ONE_USDC);
    const { proof, poolNullifierHashBuf } = await makePoolClaimProof({
      m: mint1, secrets, recipient,
    });

    const [poolNullifierPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool_nullifier_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );
    const [creditNotePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );

    // Field-valid 32-byte root that the pool tree has never seen.
    const phonyRoot = Buffer.alloc(32);
    phonyRoot[31] = 0xab;

    const inputs = Buffer.concat([phonyRoot, Buffer.from(proof.newStoredCommitment)]);

    let threw = false; let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(
        buildClaimIx({
          m: mint1, poolNullifierPDA, creditNotePDA, recipient: recipient.publicKey,
          poolNullifierHash: poolNullifierHashBuf,
          proofA: proof.proofA, proofB: proof.proofB, proofC: proof.proofC, inputs,
        })
      ), [payer], { commitment: "confirmed" });
    } catch (e: any) { threw = true; errorText = String(e?.message ?? e); }
    expect(threw).to.equal(true);
    expect(errorText).to.match(/InvalidRoot|6001|0x1771/i,
      `got unexpected error text: ${errorText}`);
  });

  it("rejects a mint↔config mismatch (cross-mint isolation)", async () => {
    const recipient = Keypair.generate();
    const secrets = await poolDeposit(mint1, 15n * ONE_USDC);
    const { proof, poolNullifierHashBuf } = await makePoolClaimProof({
      m: mint1, secrets, recipient,
    });

    const [poolNullifierPDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool_nullifier_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );
    const [creditNotePDA] = PublicKey.findProgramAddressSync(
      [Buffer.from("credit_spl"), mint1.mint.toBuffer(), poolNullifierHashBuf],
      PROGRAM_ID
    );
    const inputs = Buffer.concat([
      Buffer.from(proof.poolMerkleRoot),
      Buffer.from(proof.newStoredCommitment),
    ]);

    // Build the ix with mint=mint1 but pass mint2's mint_config in that slot.
    // Anchor seeds derive expected mint_config from mint=mint1; the passed
    // mint2 config doesn't match → ConstraintSeeds.
    const badIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: vaultPDA, isSigner: false, isWritable: true },
        { pubkey: mint2.mintConfigPDA, isSigner: false, isWritable: false }, // <-- wrong
        { pubkey: mint1.poolTreePDA, isSigner: false, isWritable: false },
        { pubkey: poolNullifierPDA, isSigner: false, isWritable: true },
        { pubkey: creditNotePDA, isSigner: false, isWritable: true },
        { pubkey: mint1.mint, isSigner: false, isWritable: false },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("claim_from_note_pool_spl"),
        poolNullifierHashBuf,
        Buffer.from(proof.proofA),
        Buffer.from(proof.proofB),
        Buffer.from(proof.proofC),
        u32LE(inputs.length),
        inputs,
      ]),
    });

    let threw = false; let errorText = "";
    try {
      await sendAndConfirmTransaction(connection, new Transaction().add(badIx),
        [payer], { commitment: "confirmed" });
    } catch (e: any) { threw = true; errorText = String(e?.message ?? e); }
    expect(threw).to.equal(true);
    expect(errorText).to.match(
      /ConstraintSeeds|ConstraintHasOne|2001|2006|0x7d1|0x7d6/i,
      `got unexpected error text: ${errorText}`
    );
  });
});
