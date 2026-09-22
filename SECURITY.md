# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report responsibly to the repository maintainer through GitHub private messaging or the contact method on the repository profile. Include a description, steps to reproduce or a proof of concept, the affected file, a suggested severity, and a suggested fix if you have one. We aim to acknowledge reports within 48 hours and give a fix timeline within 7 days.

## Scope

| Component | Location | In scope |
|-----------|----------|----------|
| Credit note claim circuit | `circuits/darkdrop.circom` | Yes |
| Note pool claim circuit | `circuits/note_pool.circom` | Yes |
| Merkle membership verifier | `circuits/lib/merkle_tree.circom` | Yes |
| Circuit test suite | `circuits/test/` | No (test utilities only) |

The chain, verifier, and client for Robin Hood Chain are not yet in this repository. Once they land, this table will grow.

## Security properties of the circuits

| Property | Mechanism |
|----------|-----------|
| No double-claim | Each proof exposes `Poseidon(nullifier)`. The verifier must reject any nullifier hash it has already seen. The circuit binds the hash to the leaf preimage so it cannot be forged. |
| Leaf privacy | The Merkle proof is a private witness. The public root proves membership without revealing which leaf. |
| Amount privacy at claim | The amount is a private input. The public `amount_commitment` is `Poseidon(amount, blinding)`, hiding and binding. |
| Amount integrity | The same amount is constrained into the leaf hash and into the commitment, so the claimed amount is exactly the deposited amount. |
| Range safety | `Num2Bits(64)` and a non-zero check bound the amount to `1 <= amount < 2^64`. |
| Recipient binding | The public `recipient` must equal `Poseidon(recipient_hi, recipient_lo)`. The mapping is injective, so a proof cannot be redirected. |
| Stored commitment unlinkability | The note pool circuit outputs `Poseidon(Poseidon(amount, new_blinding), new_salt)`, a fresh commitment for the same amount that shares nothing with the input leaf. |

## Known design limitations

These are properties of the model, not bugs.

1. **The deposit is visible.** Funding a note is a public transfer on whatever chain hosts it. The model hides the claim and decorrelates the withdrawal. It does not hide the deposit.
2. **Unverified leaf at deposit.** A depositor constructs the leaf from private data, so a verifier cannot check that the leaf's amount matches the funds sent. The note pool layer closes this for notes that pass through it, because the pool leaf is built by the verifier from a verified amount. The base layer inherits the same limitation as every commitment-scheme mixer.
3. **Anonymity set grows with use.** Privacy at the base layer is bounded by the number of leaves in the tree.
4. **Password protection is client-side only.** The circuits do not enforce a password. Password-protected claim codes rely entirely on client-side encryption of the code.

## Audit history

The Solana implementation of this model went through seven audit rounds. Those reports cover the Solana program and are kept with that code, not here. The circuit-level findings they contain have been applied to the circuits in this repository: injective recipient binding replaced the earlier squared-recipient check, and the vacuous in-circuit password gate was removed.
