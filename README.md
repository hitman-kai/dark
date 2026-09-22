# Robin Hood Chain

A new privacy architecture built on top of the **credit note model**: a two-step, zero-knowledge claim flow that breaks every public link between the party who funds a note and the party who redeems it.

This repository is the chain-agnostic foundation. It holds the credit note model, the Groth16 circuits that enforce it, and the design documents. The original implementation of the model shipped as a Solana program; that code lives in its own repository and is not part of this one. Everything here is independent of any particular chain, runtime, or token standard.

## The credit note model

A conventional mixer proves membership in a Merkle tree and pays out in the same transaction. That single transaction is the link an observer needs: it names the recipient and carries the amount. The credit note model splits it apart.

1. **Deposit.** The sender funds a note and inserts a leaf `Poseidon(secret, nullifier, amount, blinding)` into an incremental Merkle tree. The claim code (the leaf preimage) is handed to the recipient out of band.
2. **Claim.** The recipient submits a Groth16 proof of leaf membership with the amount as a **private** input. The verifier records a re-randomized commitment `Poseidon(Poseidon(amount, blinding), salt)` as a credit note and marks the nullifier spent. No value moves and no amount appears anywhere.
3. **Withdraw.** Later, from any account, the holder opens the commitment. The verifier recomputes the Poseidon hash, pays out, and destroys the note.

An observer who finds the claim sees an opaque proof, an opaque set of public inputs, and a nullifier hash. They cannot learn the amount, the deposit it corresponds to, or when the withdrawal will happen.

Two layers build on that core:

- **Note pool.** A credit note can be re-deposited into a second Merkle tree as a fresh leaf built by the verifier from the verified amount. A second proof redeems it as a brand-new credit note. An observer must break both proofs to link deposit to withdrawal.
- **Recipient binding.** Every proof commits to `Poseidon(recipient_hi, recipient_lo)`, so a claim cannot be front-run or replayed to a different recipient.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full model, the commitment scheme, and the properties each circuit enforces.

## Repository layout

| Path | Contents |
|------|----------|
| `circuits/darkdrop.circom` | Credit note claim circuit. Leaf membership, nullifier, amount commitment, 64-bit range check, recipient binding. Amount is private. |
| `circuits/note_pool.circom` | Note pool claim circuit. Same membership and nullifier logic against the pool tree, plus a re-randomized output commitment for the fresh note. |
| `circuits/lib/merkle_tree.circom` | Poseidon Merkle membership verifier, depth parameterized. |
| `circuits/test/` | Proof generation and verification test suite for the claim circuit. |
| `ARCHITECTURE.md` | The credit note model, chain-agnostic. |
| `SECURITY.md` | Reporting policy and the security properties the circuits guarantee. |
| `CONTRIBUTING.md` | Building and testing the circuits locally. |

## Status

The circuits are carried over unchanged in logic from the audited Solana build. The chain, verifier, and client for Robin Hood Chain are being designed on top of them and will be added to this repository as they take shape.

## Build

Requires [circom](https://docs.circom.io/) v2.1+ and Node 18+. See [CONTRIBUTING.md](CONTRIBUTING.md) for compiling the circuits and running the test suite.

## License

No license has been chosen for this repository yet. Until one is added, all rights are reserved by the author.
