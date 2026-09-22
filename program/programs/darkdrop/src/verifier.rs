use anchor_lang::prelude::*;
use groth16_solana::groth16::Groth16Verifier;
use crate::state::ProofData;
use crate::vk;
use crate::errors::DarkDropError;

/// BN254 scalar field order `r`, big-endian.
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
///   = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
///
/// A Groth16 public input is *canonical* iff its big-endian value is strictly
/// less than `r`. See [`is_canonical`].
pub const BN254_R_BE: [u8; 32] = [
    0x30, 0x64, 0x4E, 0x72, 0xE1, 0x31, 0xA0, 0x29,
    0xB8, 0x50, 0x45, 0xB6, 0x81, 0x81, 0x58, 0x5D,
    0x28, 0x33, 0xE8, 0x48, 0x79, 0xB9, 0x70, 0x91,
    0x43, 0xE1, 0xF5, 0x93, 0xF0, 0x00, 0x00, 0x01,
];

/// Returns true iff `value` (interpreted big-endian, matching groth16-solana's
/// public-input encoding) is a canonical BN254 scalar — strictly less than the
/// field order `r`.
///
/// Audit F1 (#17): public inputs reused as PDA seeds / uniqueness keys MUST be
/// canonical. A non-canonical `n + r` verifies against the same proof as `n`
/// (each `IC[i]` has order `r`, so `(n+r)·IC[i] = n·IC[i]`) but is a distinct
/// 32-byte string → distinct nullifier PDA → double-spend. Rejecting `>= r` at
/// the verification boundary closes this regardless of what the underlying
/// alt_bn128 syscall / groth16-solana does with non-canonical scalars.
///
/// `[u8; 32]`'s derived `Ord` is lexicographic, which over big-endian bytes is
/// exactly numeric ordering, so a plain byte-array comparison is correct.
#[inline]
pub fn is_canonical(value: &[u8; 32]) -> bool {
    *value < BN254_R_BE
}

/// Reject the proof unless every public input is a canonical BN254 scalar.
/// Called at the top of every `verify_proof*` so all live claim paths (SOL +
/// SPL, V2/V3) inherit the guard uniformly. (The V1 path that also routed
/// through this guard was retired in #18.)
fn require_canonical_inputs(public_inputs: &[[u8; 32]]) -> Result<()> {
    for input in public_inputs.iter() {
        require!(is_canonical(input), DarkDropError::NonCanonicalInput);
    }
    Ok(())
}

// The legacy V1 `verify_proof` (6 public inputs, V1 verification key) was
// removed in #18 along with the `claim` instruction it served — the V1
// circuit source was absent and could not be audited. V2/V3 verifiers below
// are unaffected; they reuse the shared alpha/beta/gamma ceremony params.

/// Verify a Groth16 proof against the V2 verification key (4 public inputs).
/// Used by `claim_credit` — amount is private, not a public input.
///
/// Public inputs order (V2):
///   [0] merkle_root
///   [1] nullifier_hash
///   [2] recipient
///   [3] amount_commitment
///
/// The former `[4] password_hash` input was removed in issue #20: the in-circuit
/// password gate was vacuous (claimer-chosen, bound to nothing), so it was deleted
/// from circuits/darkdrop.circom. Password protection is solely claim-code encryption.
pub fn verify_proof_v2(
    proof: &ProofData,
    public_inputs: &[[u8; 32]; 4],
) -> Result<()> {
    // Audit F1 (#17): reject non-canonical public inputs before verification.
    require_canonical_inputs(public_inputs)?;

    let vk = vk::verifying_key_v2();

    let mut verifier = Groth16Verifier::new(
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        public_inputs,
        &vk,
    )
    .map_err(|_| DarkDropError::InvalidProof)?;

    verifier
        .verify()
        .map_err(|_| DarkDropError::InvalidProof)?;

    Ok(())
}

#[cfg(test)]
mod canonicalization_tests {
    //! Issue #17 (F1) — non-canonical public inputs reused as PDA seeds.
    //!
    //! A Groth16 public input `n` and its malleable twin `n + r` (where `r` is
    //! the BN254 scalar field order) reduce to the SAME scalar during
    //! verification, because each `IC[i]` has order `r` and `(n+r)·IC[i] =
    //! n·IC[i]`. So one proof verifies for both values. But `n` and `n + r` are
    //! DISTINCT 32-byte strings, so they derive DISTINCT nullifier / credit
    //! PDAs — a double-spend. The program must reject any public input that is
    //! not canonical (`>= r`) at the boundary.
    //!
    //! NOTE: the *runtime* leg of the repro (does `n + r` actually verify
    //! against the deployed VK, and is a second on-chain PDA creatable) needs
    //! the alt_bn128 syscall and a deployed program — it is deploy-gated and
    //! verified during the batched devnet upgrade (issue checklist items 1–2).
    //! These host tests cover the canonical-guard predicate the fix introduces.
    use super::*;

    // BN254 scalar field order r, big-endian. Local copy so this test is an
    // independent source of truth for the malleability arithmetic, not coupled
    // to the constant the fix adds.
    const R: [u8; 32] = [
        0x30, 0x64, 0x4E, 0x72, 0xE1, 0x31, 0xA0, 0x29,
        0xB8, 0x50, 0x45, 0xB6, 0x81, 0x81, 0x58, 0x5D,
        0x28, 0x33, 0xE8, 0x48, 0x79, 0xB9, 0x70, 0x91,
        0x43, 0xE1, 0xF5, 0x93, 0xF0, 0x00, 0x00, 0x01,
    ];

    /// Big-endian 256-bit wrapping addition. Forms the malleable twin `n + r`.
    fn be_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let s = a[i] as u16 + b[i] as u16 + carry;
            out[i] = (s & 0xff) as u8;
            carry = s >> 8;
        }
        out
    }

    /// Big-endian `value - 1` (value assumed > 0).
    fn be_sub_one(a: &[u8; 32]) -> [u8; 32] {
        let mut out = *a;
        for i in (0..32).rev() {
            if out[i] == 0 {
                out[i] = 0xff;
            } else {
                out[i] -= 1;
                break;
            }
        }
        out
    }

    #[test]
    fn malleable_twin_is_rejected() {
        // A canonical nullifier (any value < r). Use 5 for determinism.
        let mut n = [0u8; 32];
        n[31] = 5;
        let n_plus_r = be_add(&n, &R);

        // The double-spend surface: n and n+r are DISTINCT byte strings, so they
        // derive DISTINCT PDAs, yet a Groth16 verifier maps both to the same
        // scalar — this is why a second nullifier PDA is creatable from one
        // proof when there is no canonical guard.
        assert_ne!(n, n_plus_r, "n and n+r must be distinct 32-byte PDA seeds");

        // The fix: accept the canonical value, reject the malleable twin.
        assert!(is_canonical(&n), "canonical nullifier must be accepted");
        assert!(
            !is_canonical(&n_plus_r),
            "malleable twin n+r must be rejected (double-spend guard)"
        );
    }

    #[test]
    fn canonical_boundary_values() {
        let zero = [0u8; 32];
        let max = [0xffu8; 32];
        let r_minus_1 = be_sub_one(&R);

        assert!(is_canonical(&zero), "0 is canonical");
        assert!(is_canonical(&r_minus_1), "r-1 is the largest canonical value");
        assert!(!is_canonical(&R), "r itself is NOT canonical");
        assert!(!is_canonical(&max), "2^256-1 is not canonical");
    }
}

/// Verify a Groth16 proof against the V3 verification key (4 public inputs).
/// Used by `claim_from_note_pool` — note pool circuit.
///
/// Public inputs order (V3):
///   [0] pool_merkle_root
///   [1] pool_nullifier_hash
///   [2] new_stored_commitment
///   [3] recipient_hash
pub fn verify_proof_v3(
    proof: &ProofData,
    public_inputs: &[[u8; 32]; 4],
) -> Result<()> {
    // Audit F1 (#17): reject non-canonical public inputs before verification.
    require_canonical_inputs(public_inputs)?;

    let vk = vk::verifying_key_v3();

    let mut verifier = Groth16Verifier::new(
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        public_inputs,
        &vk,
    )
    .map_err(|_| DarkDropError::InvalidProof)?;

    verifier
        .verify()
        .map_err(|_| DarkDropError::InvalidProof)?;

    Ok(())
}
