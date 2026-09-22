/**
 * Off-chain Groth16 proof pre-validation using snarkjs.
 *
 * Converts the on-chain proof format (raw bytes with negated A, swapped G2)
 * back to snarkjs format and verifies against the verification key.
 * This prevents gas drain attacks from invalid proofs.
 */

// @ts-ignore — snarkjs has no type declarations
import * as snarkjs from "snarkjs";
// @ts-ignore — circomlibjs has no type declarations
import { buildPoseidon } from "circomlibjs";

// Verification keys loaded once at import time
const VK_V1 = require("../../circuits/build/verification_key.json");
const VK_V2 = require("../../circuits/build/verification_key_v2.json");
// V3 (note pool) circuit. Audit 06 M-01: the pool-claim relay endpoint must
// pre-verify V3 proofs off-chain to avoid a gas-drain DoS, just as the V2
// credit endpoint does. This is the ceremony output for the note_pool circuit.
const VK_V3 = require("../../circuits/build/note_pool/verification_key_note_pool.json");

// BN254 base field modulus (Fq) — used to un-negate proof_a y-coordinate
const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// Lazy-initialized Poseidon instance
let poseidonInstance: any = null;

async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

/**
 * Replicate on-chain pubkey_to_field: Poseidon(hi_128, lo_128)
 * where hi = bytes[0..16] as BE u128, lo = bytes[16..32] as BE u128
 */
export async function pubkeyToField(pubkeyBytes: Uint8Array): Promise<bigint> {
  const poseidon = await getPoseidon();
  const hi = bytesToBigIntBE(pubkeyBytes.slice(0, 16));
  const lo = bytesToBigIntBE(pubkeyBytes.slice(16, 32));
  const hash = poseidon([hi, lo]);
  return poseidon.F.toObject(hash);
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return BigInt("0x" + (hex || "0"));
}

export function bytes32ToBigInt(buf: Buffer | Uint8Array, offset: number = 0): bigint {
  let hex = "";
  for (let i = 0; i < 32; i++) {
    hex += buf[offset + i].toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex);
}

/**
 * Convert raw 64-byte G1 (with negated y) back to snarkjs format [x, y, "1"]
 * Frontend sends: [x_BE(32) || neg_y_BE(32)]
 * snarkjs wants: [x_str, y_str, "1"] with original (un-negated) y
 */
function g1NegFromBytes(buf: Buffer | Uint8Array): string[] {
  const x = bytes32ToBigInt(buf, 0);
  const negY = bytes32ToBigInt(buf, 32);
  const y = BN254_FQ - negY; // un-negate
  return [x.toString(), y.toString(), "1"];
}

/**
 * Convert raw 64-byte G1 back to snarkjs format [x, y, "1"]
 */
function g1FromBytes(buf: Buffer | Uint8Array): string[] {
  const x = bytes32ToBigInt(buf, 0);
  const y = bytes32ToBigInt(buf, 32);
  return [x.toString(), y.toString(), "1"];
}

/**
 * Convert raw 128-byte G2 back to snarkjs format [[x0, x1], [y0, y1], ["1", "0"]]
 * On-chain encoding: [x1_BE(32) || x0_BE(32) || y1_BE(32) || y0_BE(32)]
 * snarkjs wants: [[x0, x1], [y0, y1], ["1", "0"]]
 */
function g2FromBytes(buf: Buffer | Uint8Array): string[][] {
  const x1 = bytes32ToBigInt(buf, 0);
  const x0 = bytes32ToBigInt(buf, 32);
  const y1 = bytes32ToBigInt(buf, 64);
  const y0 = bytes32ToBigInt(buf, 96);
  return [
    [x0.toString(), x1.toString()],
    [y0.toString(), y1.toString()],
    ["1", "0"],
  ];
}

/**
 * Verify a V1 claim proof off-chain.
 *
 * Public inputs order (from circuit + on-chain claim.rs):
 *   [amount, merkle_root, nullifier_hash, recipient_hash, amount_commitment, password_hash]
 */
export async function verifyClaimProofV1(
  proofA: number[],
  proofB: number[],
  proofC: number[],
  publicInputs: bigint[],
): Promise<boolean> {
  const proof = {
    pi_a: g1NegFromBytes(Buffer.from(proofA)),
    pi_b: g2FromBytes(Buffer.from(proofB)),
    pi_c: g1FromBytes(Buffer.from(proofC)),
    protocol: "groth16" as const,
    curve: "bn128",
  };

  const signals = publicInputs.map((v) => v.toString());

  return snarkjs.groth16.verify(VK_V1, signals, proof);
}

/**
 * Verify a V2 claim_credit proof off-chain.
 *
 * Public inputs order (from circuit + on-chain claim_credit.rs):
 *   [merkle_root, nullifier_hash, recipient_hash, amount_commitment]
 *   (issue #20: the password_hash public input was removed)
 */
/**
 * Verify a credit note commitment opening off-chain.
 * Recomputes: Poseidon(Poseidon(amount_BE, blinding), salt) and compares
 * against the stored commitment from the CreditNote PDA.
 *
 * @param storedCommitment - 32 bytes from on-chain CreditNote.commitment
 * @param amount - u64 amount in lamports
 * @param blindingFactor - 32 bytes
 * @param salt - 32 bytes
 * @returns true if the opening matches the stored commitment
 */
export async function verifyCommitmentOpening(
  storedCommitment: Uint8Array,
  amount: bigint,
  blindingFactor: Uint8Array,
  salt: Uint8Array,
): Promise<boolean> {
  const poseidon = await getPoseidon();

  // amount as big-endian 32-byte field element (matches on-chain u64_to_field_be)
  const amountHex = amount.toString(16).padStart(64, "0");
  const amountBigInt = BigInt("0x" + amountHex);

  const blindingBigInt = bytesToBigIntBE(blindingFactor);
  const saltBigInt = bytesToBigIntBE(salt);

  // original = Poseidon(amount, blinding)
  const original = poseidon([amountBigInt, blindingBigInt]);
  const originalField = poseidon.F.toObject(original);

  // stored = Poseidon(original, salt)
  const computed = poseidon([originalField, saltBigInt]);
  const computedField = poseidon.F.toObject(computed);

  // Compare against stored commitment (big-endian bytes)
  const storedBigInt = bytesToBigIntBE(storedCommitment);

  return computedField === storedBigInt;
}

export async function verifyClaimProofV2(
  proofA: number[],
  proofB: number[],
  proofC: number[],
  publicInputs: bigint[],
): Promise<boolean> {
  const proof = {
    pi_a: g1NegFromBytes(Buffer.from(proofA)),
    pi_b: g2FromBytes(Buffer.from(proofB)),
    pi_c: g1FromBytes(Buffer.from(proofC)),
    protocol: "groth16" as const,
    curve: "bn128",
  };

  const signals = publicInputs.map((v) => v.toString());

  return snarkjs.groth16.verify(VK_V2, signals, proof);
}

/**
 * Verify a V3 claim_from_note_pool proof off-chain (Audit 06 M-01).
 *
 * Public-input order MUST match the on-chain verifier
 * (claim_from_note_pool.rs):
 *   [0] pool_merkle_root
 *   [1] pool_nullifier_hash
 *   [2] new_stored_commitment
 *   [3] recipient_hash = Poseidon(pubkey_hi_128, pubkey_lo_128)
 *
 * @param poolMerkleRoot      32 bytes (inputs[0..32])
 * @param poolNullifierHash   32 bytes
 * @param newStoredCommitment 32 bytes (inputs[32..64])
 * @param recipient           32-byte recipient pubkey
 */
export async function verifyClaimProofV3(
  proofA: number[],
  proofB: number[],
  proofC: number[],
  poolMerkleRoot: Uint8Array,
  poolNullifierHash: Uint8Array,
  newStoredCommitment: Uint8Array,
  recipient: Uint8Array,
): Promise<boolean> {
  const proof = {
    pi_a: g1NegFromBytes(Buffer.from(proofA)),
    pi_b: g2FromBytes(Buffer.from(proofB)),
    pi_c: g1FromBytes(Buffer.from(proofC)),
    protocol: "groth16" as const,
    curve: "bn128",
  };

  const recipientHash = await pubkeyToField(recipient);

  const signals = [
    bytesToBigIntBE(poolMerkleRoot),
    bytesToBigIntBE(poolNullifierHash),
    bytesToBigIntBE(newStoredCommitment),
    recipientHash,
  ].map((v) => v.toString());

  return snarkjs.groth16.verify(VK_V3, signals, proof);
}
