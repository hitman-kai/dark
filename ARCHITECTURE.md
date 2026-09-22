# The Credit Note Architecture

This document describes the credit note model independently of any chain. It defines the data the model commits to, the three operations that move a note through its life, the note pool layer on top, and the exact statements each circuit proves. A verifier for Robin Hood Chain must implement the state and checks in the "Verifier obligations" sections; everything else is fixed by the circuits.

All hashes are Poseidon over the BN254 scalar field. Proofs are Groth16 over BN254.

---

## 1. Why split the claim

In a single-step mixer, one transaction proves membership and pays the recipient. That transaction is the pivot an observer uses: it carries the recipient and, in most designs, the amount. Even when the amount is hidden in the proof, the payout that follows reveals it in the same place.

The credit note model separates *proving the right to value* from *moving the value*:

- **Claim** proves membership and mints a credit note. The amount is a private witness. Nothing is paid.
- **Withdraw** opens the note and pays. It is a separate action, from any account, at any later time, and shares nothing with the claim that an observer can use to join them.

The claim is the only place where deposit-side and recipient-side information meet, and the claim contains no amount and no value movement.

---

## 2. Data model

### Note leaf

A note is a leaf in an incremental Merkle tree of depth 20:

```
leaf = Poseidon(secret, nullifier, amount, blinding)
```

| Field | Size | Who chooses it | Purpose |
|-------|------|----------------|---------|
| `secret` | field element | depositor, random | Makes the leaf unguessable |
| `nullifier` | field element | depositor, random | Spent marker, revealed only as a hash |
| `amount` | 64-bit integer, non-zero | depositor | Value of the note in base units |
| `blinding` | field element | depositor, random | Blinds the amount commitment |

The four values together are the **claim code**. They are handed to the recipient out of band and are never written to public state.

### Nullifier hash

```
nullifier_hash = Poseidon(nullifier)
```

Published at claim time. The verifier keeps a set of spent nullifier hashes and rejects any repeat. Because the hash is bound to the leaf inside the proof, it cannot be forged for a leaf the prover does not know, and it cannot be linked back to the leaf by anyone who does not know the nullifier.

### Amount commitment

```
amount_commitment = Poseidon(amount, blinding)
```

Published at claim time as a public input. Hiding because `blinding` is random; binding because Poseidon is collision resistant.

### Stored commitment (the credit note)

The verifier does not store `amount_commitment` directly. It stores a re-randomized form:

```
stored_commitment = Poseidon(amount_commitment, salt)
```

`salt` is fresh randomness supplied by the claimer. The re-randomization means the value written to state does not equal any value that appeared in the proof's public inputs, so an observer cannot pattern-match the claim to the note it created.

### Recipient binding

Addresses on most chains are 256 bits, wider than the BN254 scalar field. The circuit therefore takes the recipient as two 128-bit halves and binds the proof to their hash:

```
recipient = Poseidon(recipient_hi, recipient_lo)
```

`recipient` is a public input. The verifier recomputes it from the account that will hold the note and rejects a mismatch. The mapping is injective over the halves, so no second address satisfies the same proof.

---

## 3. Base layer: deposit, claim, withdraw

### Deposit

```
Depositor:
  draw secret, nullifier, blinding at random
  choose amount
  leaf = Poseidon(secret, nullifier, amount, blinding)
  send amount to the treasury
  submit leaf

Verifier:
  accept the funds
  append leaf to the note tree
  push the new root onto the root history
```

The deposit is public. The verifier cannot check that `leaf` encodes the amount received, because the leaf commits to secrets it does not know. This is the standard trust boundary of commitment-scheme mixers and it is closed by the note pool layer below.

### Claim

```
Recipient:
  reconstruct the Merkle path for the leaf against a root in the root history
  draw salt at random
  prove ClaimStatement with public inputs
    (merkle_root, nullifier_hash, recipient, amount_commitment)
  submit proof, public inputs, salt

Verifier:
  reject unless merkle_root is in the root history
  reject unless nullifier_hash is unseen; then mark it spent
  reject unless recipient == Poseidon(hi, lo) of the note holder's address
  verify the Groth16 proof
  create a credit note holding
    stored_commitment = Poseidon(amount_commitment, salt)
    nullifier_hash
    holder
```

No value moves. The amount does not appear in the public inputs, the state, or the transaction.

### Withdraw

```
Holder:
  submit (amount, blinding, salt)

Verifier:
  reject unless Poseidon(Poseidon(amount, blinding), salt) == stored_commitment
  reject unless the caller is the note holder
  pay amount, less any fee computed from a rate, to the holder
  destroy the credit note
```

The withdrawal reveals the amount by paying it, but it is a separate action with no field in common with the claim except the destroyed note's identity, and that identity is never linked to a leaf.

### What an observer sees

| Data | Deposit | Claim | Withdraw |
|------|---------|-------|----------|
| Depositor | visible | absent | absent |
| Recipient | absent | visible | visible |
| Amount | visible | hidden | visible as a balance change |
| Which leaf | n/a | hidden by the proof | n/a |
| Link deposit to claim | | none | |
| Link claim to withdraw | | | none beyond the note identity, which is unlinkable to any leaf |

---

## 4. Note pool layer

The note pool is a second Merkle tree whose leaves are constructed by the verifier, not the depositor. It provides two things: a second proof an observer must break, and a leaf whose amount is guaranteed correct.

### Deposit to pool

```
Holder of a credit note:
  draw pool_secret, pool_nullifier, pool_blinding at random
  submit (amount, blinding, salt) and (pool_secret, pool_nullifier, pool_blinding)

Verifier:
  reject unless Poseidon(Poseidon(amount, blinding), salt) == stored_commitment
  pool_leaf = Poseidon(pool_secret, pool_nullifier, amount, pool_blinding)   <- built by the verifier
  append pool_leaf to the pool tree
  destroy the credit note
```

Because the verifier builds the leaf from an amount it has just verified, a dishonest leaf cannot enter the pool. A one-step variant lets a depositor fund a pool leaf directly from a public transfer; the verifier builds the leaf from the amount received.

### Claim from pool

```
Recipient:
  reconstruct the pool Merkle path
  draw new_blinding, new_salt at random
  prove PoolClaimStatement with public inputs
    (pool_merkle_root, pool_nullifier_hash, new_stored_commitment, recipient_hash)

Verifier:
  reject unless pool_merkle_root is in the pool root history
  reject unless pool_nullifier_hash is unseen; then mark it spent
  reject unless recipient_hash matches the holder's address
  verify the Groth16 proof
  create a fresh credit note with stored_commitment = new_stored_commitment
```

The fresh note carries the same amount under entirely new randomness. It is withdrawn exactly as a base-layer note. An observer must defeat both the base-layer claim proof and the pool claim proof to connect the original deposit to the final withdrawal.

Pool nullifiers live in a separate namespace from base-layer nullifiers.

---

## 5. Circuit statements

### ClaimStatement (`circuits/darkdrop.circom`)

**Public inputs, in order:** `merkle_root`, `nullifier_hash`, `recipient`, `amount_commitment`

**Private inputs:** `secret`, `amount`, `blinding_factor`, `nullifier`, `merkle_path[20]`, `merkle_indices[20]`, `recipient_hi`, `recipient_lo`

The prover knows private inputs such that:

1. `leaf = Poseidon(secret, nullifier, amount, blinding_factor)`
2. `leaf` is at the position given by `merkle_indices` in a tree with root `merkle_root`, with siblings `merkle_path`; every index is 0 or 1
3. `nullifier_hash == Poseidon(nullifier)`
4. `amount_commitment == Poseidon(amount, blinding_factor)`
5. `0 < amount < 2^64`
6. `recipient == Poseidon(recipient_hi, recipient_lo)`

Roughly 5,900 constraints at depth 20.

### PoolClaimStatement (`circuits/note_pool.circom`)

**Public inputs, in order:** `pool_merkle_root`, `pool_nullifier_hash`, `new_stored_commitment`, `recipient_hash`

**Private inputs:** `pool_secret`, `pool_nullifier`, `amount`, `pool_blinding_factor`, `pool_path[20]`, `pool_indices[20]`, `new_blinding`, `new_salt`, `recipient_hi`, `recipient_lo`

The prover knows private inputs such that:

1. `pool_leaf = Poseidon(pool_secret, pool_nullifier, amount, pool_blinding_factor)`
2. `pool_leaf` is in the tree with root `pool_merkle_root` at `pool_indices` with siblings `pool_path`
3. `pool_nullifier_hash == Poseidon(pool_nullifier)`
4. `0 < amount < 2^64`
5. `new_stored_commitment == Poseidon(Poseidon(amount, new_blinding), new_salt)`
6. `recipient_hash == Poseidon(recipient_hi, recipient_lo)`

Constraint 5 is what carries the amount across the pool boundary: the new note commits to the same `amount` that the pool leaf was built from, and the verifier never sees it.

Roughly 6,200 constraints at depth 20.

### Merkle verifier (`circuits/lib/merkle_tree.circom`)

Standard Poseidon(2) membership check. At each level a `Switcher` orders `(current, sibling)` by the index bit, the pair is hashed, and the final value is constrained equal to the public root. The circuit enforces that each index bit is binary.

---

## 6. Verifier obligations

A verifier for this model, on any chain, must maintain:

| State | Purpose |
|-------|---------|
| Note tree: filled subtrees, next index, root history | Incremental Merkle tree; the root history lets claims verify against a root from insertion time rather than the current root |
| Pool tree: same shape | Second tree for the note pool |
| Spent nullifier set, base layer | One entry per `nullifier_hash`; insert-once semantics |
| Spent nullifier set, pool layer | Separate namespace |
| Credit notes: `stored_commitment`, `nullifier_hash`, holder | Created at claim, destroyed at withdraw or pool deposit |
| Treasury | Holds deposited value; must remain solvent against outstanding notes |

And must enforce, outside the circuits:

- Root history membership for every claim, base or pool.
- Insert-once on each nullifier set. This is the double-spend guard; the circuit only binds the hash.
- Recipient equality: recompute `Poseidon(hi, lo)` from the holder's address and compare to the public input.
- Commitment opening at withdraw and at pool deposit.
- Holder authorization at withdraw and at pool deposit.
- Treasury solvency: never pay more than the treasury holds, and never let an administrative sweep dip below outstanding obligations.
- Fee as a bounded rate, never a plaintext amount parameter.
- Public input order exactly as listed in section 5. Verification keys are bound to it.

A root history of 256 entries was sufficient for the original deployment to keep claim codes valid for one to two weeks of activity. Size it for the expected deposit rate.

---

## 7. Claim code

The claim code is the recipient's only credential. Its content is:

| Field | Meaning |
|-------|---------|
| `s` | secret |
| `n` | nullifier (or `pool_nullifier` for pool notes) |
| `a` | amount in base units |
| `b` | blinding (or `pool_blinding` for pool notes) |
| `i` | leaf index |
| `p` | optional tree snapshot at insertion (root plus filled subtrees) so the path can be rebuilt without scanning history |
| `f` | flavor: base layer or pool |

Encoding is an implementation choice. The original build serialized this as JSON, base64url encoded, with an optional PBKDF2-derived AES-256-GCM layer for password protection. Password protection is entirely client-side; the circuits do not enforce it.

---

## 8. Design decisions carried over

- **Poseidon for everything.** Pedersen commitments would need elliptic-curve arithmetic inside the circuit at roughly 150k extra constraints on BN254. Poseidon is hiding, binding, and cheap in-circuit.
- **Amount is private at claim.** An earlier version exposed the amount as a public input. Moving it to a private witness is the change that created the credit note model. The leaf hash, the commitment, and the range check still constrain it.
- **Injective recipient binding.** An earlier check constrained `recipient * recipient`, which is satisfied by both `r` and `p - r`. Hashing the two halves removes the ambiguity.
- **No password gate in-circuit.** A password hash that is committed neither to the leaf nor to state can be set to zero by anyone holding the preimage, so it protected nothing. It was removed.
- **Re-randomized stored commitment.** Storing `Poseidon(amount_commitment, salt)` instead of `amount_commitment` removes the one value that appeared in both the proof's public inputs and the created note.
- **Verifier-built pool leaves.** The pool closes the unverified-leaf gap of the base layer by never letting a depositor supply a pool leaf.
