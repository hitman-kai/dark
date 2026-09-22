use light_hasher::{Hasher, Poseidon};
use anchor_lang::prelude::Pubkey;

/// Compute Poseidon hash of two 32-byte inputs.
/// Used for Merkle tree interior nodes: hash(left, right).
pub fn poseidon_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[left, right]).unwrap()
}

/// Compute Poseidon hash of a single 32-byte input.
/// Used for nullifier_hash = Poseidon(nullifier) — matches the circuit constraint.
pub fn poseidon_hash_1(input: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[input]).unwrap()
}

/// Compute Poseidon hash of four 32-byte inputs.
/// Used for pool leaf construction: Poseidon(secret, nullifier, amount, blinding).
pub fn poseidon_hash_4(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32], d: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[a, b, c, d]).unwrap()
}

/// Get zero hashes for each level of the Merkle tree.
/// zero[0] = 0x00..00
/// zero[i+1] = Poseidon(zero[i], zero[i])
pub fn zero_hashes() -> Vec<[u8; 32]> {
    Poseidon::zero_bytes().to_vec()
}

/// Convert a Pubkey to a BN254 field element via Poseidon hash.
///
/// On-chain mirror of the V2/V3 circuit's recipient binding: split the 32-byte
/// pubkey into two 128-bit halves (each right-aligned in a 32-byte word) and
/// hash them as `Poseidon(hi, lo)`. This is safety-critical — it MUST match the
/// circuit's encoding or every claim flow fails with `InvalidProof`. Audit 06
/// L-03 consolidated the previously-duplicated copies here to remove drift risk.
pub fn pubkey_to_field(pubkey: &Pubkey) -> [u8; 32] {
    let bytes = pubkey.to_bytes();
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..32].copy_from_slice(&bytes[0..16]);
    lo[16..32].copy_from_slice(&bytes[16..32]);
    poseidon_hash(&hi, &lo)
}

/// Convert a u64 to a 32-byte big-endian field element.
///
/// On-chain mirror of the JS `amountToFieldBE` and the circuit's amount
/// encoding. Safety-critical for the same reason as [`pubkey_to_field`]; Audit
/// 06 L-03 consolidated the duplicated copies here.
pub fn u64_to_field_be(val: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    bytes
}
