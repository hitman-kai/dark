# Robin Hood Chain: Private Transfer Protocol

**Status:** Draft 0.1, for design review. Nothing here is final.

This document specifies private value transfer on Robin Hood Chain as an extension of the credit note model in [ARCHITECTURE.md](ARCHITECTURE.md). Read that first. This document assumes its data model, hash conventions, and verifier obligations, and changes only what it says it changes.

---

## 0. The idea in one paragraph

The credit note model has one principle that no other private transfer system is built on: **a proof never moves value, it only rewrites who is owed what.** Value enters and leaves the system in plain public steps; everything in between is a chain of obligations, each one re-randomized so that no two records share a value an observer could join. This protocol takes that principle chain-wide. A transfer is not a payment. It is an **offer**: the sender proves they gave up value and writes an obligation addressed to the recipient. The recipient **claims** the offer into their own wallet with a proof, at a time of their choosing. An unclaimed offer can be **reclaimed** by the sender after it expires. Value leaves the system through a **settlement** that is paid in epoch batches, so the moment of payout says nothing about the moment of the request. The result is a private transfer that is recoverable, refusable, and receipted, three properties that shielded pools built on the Zcash lineage do not have, without giving up sender, recipient, amount, or graph privacy.

---

## 1. Goals and threat model

### Hidden from everyone except the parties

| Fact | Transfer | Claim | Settlement |
|------|----------|-------|------------|
| Who sent | hidden | hidden | hidden |
| Who received | hidden | hidden | payout address visible |
| Amount | hidden | hidden | visible at payout, decorrelated |
| Which notes were spent | hidden | hidden | hidden |
| Link between any two operations | none | none | none |

### Visible by design

- Shield: the depositor and the amount entering the system.
- Settlement payout: the payout address and the amount leaving the system.
- Fees: the fee amount on each transfer, quantized to fixed tiers so it carries little information.
- Counts: the number of operations of each kind per block.

### What a sender learns about the recipient

Exactly one bit: **whether the offer was claimed before it expired.** This is the private delivery receipt. The sender learns nothing about the note the recipient now holds, when it will be spent, or where it goes.

### Adversaries considered

- A passive observer with the full chain history.
- A sender who tries to trace what happened to what they sent.
- A recipient who tries to identify the sender beyond what the sender chose to disclose.
- A malicious depositor who tries to create value from nothing.
- Anyone who tries to spend a note twice, or claim and reclaim the same offer.

### Out of scope

- Network-level privacy (IP addresses, timing of broadcast). Use a mixnet or relays.
- Hiding that a given account participates in the private system at all.

---

## 2. Three principles, carried over and generalized

**P1. No proof moves value.** Every zero-knowledge proof on the chain creates or destroys obligations. The only operations that move value are shield (a public deposit) and settlement payout (a proof-free opening). This is what makes every proof transaction look the same from outside: opaque proof, opaque public inputs, one or two new commitments, one or two spent nullifiers.

**P2. Ownership is established by claiming, not by sending.** A note someone else created for you is never spendable as-is. It sits in the inbox tree as an offer until you claim it into your wallet tree with fresh randomness. The sender wrote the offer and knows its contents; the sender does not know, and can never learn, the wallet note that replaces it. This is the note pool's claim step, made mandatory for every incoming value.

**P3. The chain builds every leaf whose amount it can verify.** Shield leaves are built by the verifier from the amount it received. Transfer outputs, whose amounts are private, are built by the prover under constraints that force them to balance. There is no path by which a user-chosen leaf with an unverified amount enters a tree.

---

## 3. Keys and addresses

All keys are field elements of BN254's scalar field unless noted. `Poseidon` is the same function as in the circuits. Domain separators are small constants.

```
sk        spending key, random
nk   = Poseidon(sk, DOMAIN_NK)         nullifier key, derives nullifiers
pk   = Poseidon(sk, DOMAIN_PK)         spend authority, appears inside note commitments
esk  = Poseidon(sk, DOMAIN_ESK) mod l  encryption secret, a BabyJubJub scalar
epk  = esk * B                          encryption public key, a BabyJubJub point
```

| Key set | Contents | Can |
|---------|----------|-----|
| Spending key | `sk` | Everything |
| Full viewing key | `nk`, `pk`, `esk` | See incoming notes, detect own spends, cannot spend |
| Incoming viewing key | `pk`, `esk` | See incoming notes only |
| Address | `pk`, `epk` | Receive |

An address is `(pk, epk)` encoded as one string with a checksum. Addresses never appear on chain. They appear only inside hashes and inside encrypted payloads.

**Why `pk` is a hash and not a curve point.** Every in-circuit use of the address is a Poseidon input, so a field element is the cheapest representation. The curve point `epk` is needed only for encryption, which happens outside the circuit.

---

## 4. Notes

Every leaf in every tree has the same two-level shape:

```
inner = Poseidon(pk, blinding, rho, tag)
leaf  = Poseidon(inner, amount)
```

| Field | Chosen by | Meaning |
|-------|-----------|---------|
| `pk` | owner | Spend authority. Hidden inside the hash. |
| `blinding` | note creator | Random. Makes `inner` unguessable. |
| `rho` | note creator | Random. Nullifier seed. |
| `tag` | note creator | Wallet notes: 0. Inbox notes: the expiry epoch. Gift notes: the expiry epoch. |
| `amount` | verified or constrained | 64-bit, may be zero for padding outputs |

The two-level shape is the mechanism behind P3: the verifier can build `leaf` from a user-supplied `inner` and an amount it has verified, without learning anything inside `inner`.

### Nullifiers

Wallet notes:

```
nf = Poseidon(nk, rho)
```

Only the owner can compute it, because only the owner has `nk`. The creator of the note, who chose `rho`, cannot. This is why a sender cannot watch a recipient's spends.

Inbox notes and gift notes:

```
nf = Poseidon(rho, DOMAIN_INBOX)
```

Computable by anyone who knows `rho`, which means both the sender and the recipient. This is deliberate: claim and reclaim must share one nullifier so that exactly one of them can ever succeed. The price is the delivery receipt in section 1: the sender can recognize the claim of their own offer. The sender cannot recognize anything else.

The two nullifier sets are separate namespaces.

### Relation to the credit note leaf

The credit note leaf `Poseidon(secret, nullifier, amount, blinding)` becomes a gift note with `pk = Poseidon(secret, DOMAIN_GIFT)`, `rho = nullifier`, and `tag = expiry`. The claim code carries the same four values it carries today.

---

## 5. State

| Tree or set | Leaves | Purpose |
|-------------|--------|---------|
| Wallet tree | notes owned by claimants | The only tree the transfer circuit spends from |
| Inbox tree | offers and gifts | Where value waits to be claimed or reclaimed |
| Wallet nullifier set | `Poseidon(nk, rho)` | Insert-once |
| Inbox nullifier set | `Poseidon(rho, DOMAIN_INBOX)` | Insert-once |
| Settlement queue | tickets, keyed by epoch | Openings awaiting batch payout |
| Treasury | public balance | Backs every obligation |

Each tree is an incremental Poseidon Merkle tree of depth 20 with a root history of at least 256 roots. The two trees are separate so that the transfer circuit, the claim circuit, and the reclaim circuit each prove membership in exactly one tree and cannot be confused about which.

**Time** is measured in epochs. An epoch is a fixed number of blocks, sized so that one epoch is long enough for settlement batching to be meaningful (on the order of minutes to an hour) and short enough that expiry granularity is useful. Expiry values are epoch numbers.

---

## 6. Operations

Every operation is listed with what the user submits, what the verifier checks, and what changes. Groth16 proofs are over BN254. Public inputs are listed in the order the verification key expects them.

### 6.1 Shield

Public deposit into the wallet tree. No proof.

```
User submits:   amount, inner
Verifier:       receive amount into the treasury
                leaf = Poseidon(inner, amount)
                append leaf to the wallet tree
```

Visible: depositor, amount. Hidden: `pk`, so the depositor's future notes are not linked to this deposit by anything on chain.

### 6.2 Gift

Public deposit into the inbox tree, claimable by whoever holds the claim code. This is the credit note deposit unchanged, with an expiry.

```
User submits:   amount, inner, expiry
Verifier:       receive amount into the treasury
                leaf = Poseidon(inner, amount)      (tag inside inner must equal expiry; the claim circuit enforces this)
                append leaf to the inbox tree
```

### 6.3 Transfer

Spends two wallet notes and creates one inbox note (the payment) and one wallet note (the change). Either input may be a dummy. Either output may be zero.

```
Sender submits: proof
                public inputs: wallet_root, nf_1, nf_2, out_inbox_leaf, out_wallet_leaf, fee, expiry
                encrypted payload for the recipient (section 8)
Verifier:       wallet_root is in the wallet root history
                nf_1 and nf_2 are unseen; insert both
                fee is one of the allowed fee tiers
                expiry is a valid future epoch within the allowed window
                verify proof
                append out_inbox_leaf to the inbox tree
                append out_wallet_leaf to the wallet tree
                credit fee from the treasury to the block producer's public balance
```

Value never moves in the transfer. The treasury's obligations are rebalanced: two notes worth `a1 + a2` are replaced by two notes worth `a1 + a2 - fee`, and `fee` becomes a public obligation to the producer, paid from the treasury in the same block.

### 6.4 Claim

Converts an inbox note (an offer or a gift) into a wallet note with fresh randomness. Must happen before the offer expires.

```
Recipient submits: proof
                   public inputs: inbox_root, nf_inbox, out_wallet_leaf, expiry
Verifier:          inbox_root is in the inbox root history
                   nf_inbox is unseen; insert
                   current_epoch < expiry
                   verify proof
                   append out_wallet_leaf to the wallet tree
```

The sender, watching the inbox nullifier set, sees `nf_inbox` appear and knows the offer was claimed. Nothing else about this transaction is recognizable to them.

### 6.5 Reclaim

Returns an expired, unclaimed inbox note to its sender as a fresh wallet note.

```
Sender submits: proof
                public inputs: inbox_root, nf_inbox, out_wallet_leaf, expiry
Verifier:       inbox_root is in the inbox root history
                nf_inbox is unseen; insert
                current_epoch >= expiry
                verify proof
                append out_wallet_leaf to the wallet tree
```

Claim and reclaim share the inbox nullifier, so an offer resolves exactly one way. Claim requires knowing the recipient's `pk` preimage relationship (section 7.2); reclaim requires knowing the original `inner` preimage, which only the sender has. Because the sender created the note, the sender can always reclaim; because the recipient's `sk` is never involved, the recipient can never block a reclaim after expiry except by claiming first.

### 6.6 Settle

Turns wallet notes into a payout, in two steps. The first is a proof that creates a settlement ticket. The second is a proof-free opening.

```
Step 1, request:
Holder submits: proof
                public inputs: wallet_root, nf_1, nf_2, ticket, payout_hash, fee
Verifier:       wallet_root in history; nf_1, nf_2 unseen; insert
                verify proof
                record ticket = Poseidon(Poseidon(amount, blinding), salt) in the settlement queue
                    together with payout_hash
                credit fee to the producer

Step 2, open (any later epoch):
Holder submits: amount, blinding, salt
Verifier:       Poseidon(Poseidon(amount, blinding), salt) == a queued ticket
                payout_hash == Poseidon(hi, lo) of the calling account
                move the ticket to the current epoch's payout batch

At each epoch boundary:
Verifier:       pay every ticket in the batch, in an order derived from the batch's own contents
                    (for example sorted by ticket hash), and delete them
```

The ticket is the credit note of the original model, unchanged. What is new is the batch: every payout in an epoch happens at the same block, in an order that depends on the tickets rather than on when they were opened, so an observer cannot pair a request with its payout by timing.

---

## 7. Circuit statements

Three new circuits and one carried over. Depth 20 throughout. Constraint counts are estimates from the existing circuits and will be measured.

### 7.1 Transfer

**Public inputs:** `wallet_root, nf_1, nf_2, out_inbox_leaf, out_wallet_leaf, fee, expiry`

**Private inputs:** for each input `i` in {1, 2}: `sk_i` (or a proof of `nk_i`, `pk_i` derivation), `blinding_i, rho_i, amount_i, path_i[20], indices_i[20], enabled_i`; for the inbox output: `pk_r, blinding_o, rho_o, amount_o`; for the change output: `blinding_c, rho_c, amount_c`.

The prover knows private inputs such that, for each input `i`:

1. `nk_i = Poseidon(sk_i, DOMAIN_NK)` and `pk_i = Poseidon(sk_i, DOMAIN_PK)`
2. `inner_i = Poseidon(pk_i, blinding_i, rho_i, 0)` and `leaf_i = Poseidon(inner_i, amount_i)`
3. If `enabled_i = 1`: `leaf_i` is in the tree with root `wallet_root` at `indices_i` with siblings `path_i`. If `enabled_i = 0`: `amount_i = 0` and membership is not checked.
4. `nf_i = Poseidon(nk_i, rho_i)`
5. `enabled_i` is binary; each index bit is binary

And for the outputs:

6. `out_inbox_leaf = Poseidon(Poseidon(pk_r, blinding_o, rho_o, expiry), amount_o)`
7. `out_wallet_leaf = Poseidon(Poseidon(pk_1, blinding_c, rho_c, 0), amount_c)`. Change goes to the first input's owner.
8. `0 <= amount_o < 2^64`, `0 <= amount_c < 2^64`
9. `amount_1 + amount_2 == amount_o + amount_c + fee`, with `fee < 2^64`

Constraint 9 is the conservation law. Because input amounts are bound by leaf membership and output amounts are range-checked, no combination of witnesses creates value. Two dummy inputs with a nonzero output would need `0 == amount_o + amount_c + fee` and fail.

**Why two nullifiers are always published.** A dummy input still yields a nullifier `Poseidon(nk, rho)` for a random `rho`. It is inserted like any other. Observers cannot tell dummy from real, so a one-input transfer looks identical to a two-input one.

Estimated constraints: two membership proofs at about 4,100 each, eleven Poseidon instances, two range checks, roughly 11,000.

### 7.2 Claim

**Public inputs:** `inbox_root, nf_inbox, out_wallet_leaf, expiry`

**Private inputs:** `sk, blinding_in, rho_in, amount, path[20], indices[20], blinding_out, rho_out`

1. `pk = Poseidon(sk, DOMAIN_PK)`
2. `leaf_in = Poseidon(Poseidon(pk, blinding_in, rho_in, expiry), amount)` is in the tree with root `inbox_root`
3. `nf_inbox = Poseidon(rho_in, DOMAIN_INBOX)`
4. `out_wallet_leaf = Poseidon(Poseidon(pk, blinding_out, rho_out, 0), amount)`
5. `0 < amount < 2^64`

Constraint 1 is what makes claiming an act of ownership: the note was addressed to `pk`, and only the holder of `sk` can produce `pk` inside the proof. Constraint 4 carries the amount across with fresh `blinding_out` and `rho_out`, so the wallet note shares nothing with the inbox note except the amount, which is hidden in both.

For gift notes the same circuit applies with `sk` replaced by the claim code secret and `DOMAIN_PK` by `DOMAIN_GIFT`. A one-bit private selector picks the domain; both derivations are computed and the selector chooses.

Estimated constraints: about 5,500.

### 7.3 Reclaim

**Public inputs:** `inbox_root, nf_inbox, out_wallet_leaf, expiry`

**Private inputs:** `pk_r, blinding_in, rho_in, amount, path[20], indices[20], sk_sender, blinding_out, rho_out`

1. `leaf_in = Poseidon(Poseidon(pk_r, blinding_in, rho_in, expiry), amount)` is in the tree with root `inbox_root`
2. `nf_inbox = Poseidon(rho_in, DOMAIN_INBOX)`
3. `pk_s = Poseidon(sk_sender, DOMAIN_PK)`
4. `out_wallet_leaf = Poseidon(Poseidon(pk_s, blinding_out, rho_out, 0), amount)`
5. `0 < amount < 2^64`

Reclaim proves knowledge of the inbox note's full preimage, which the sender has because the sender built it. It does not prove that `sk_sender` is related to the note in any way, and it does not need to: anyone who knows the full preimage of an unclaimed, expired offer is by construction its creator, because `blinding_in` and `rho_in` are random values that were only ever in the sender's possession and the recipient's encrypted payload. A recipient who lets an offer expire and then tries to reclaim it into their own wallet would succeed, and that is acceptable: they could have claimed it before expiry anyway.

Estimated constraints: about 5,300.

### 7.4 Settle request

The transfer circuit with the inbox output replaced by a ticket:

**Public inputs:** `wallet_root, nf_1, nf_2, ticket, payout_hash, fee`

Constraints 1 through 5 as in transfer, then:

6. `ticket = Poseidon(Poseidon(amount_t, blinding_t), salt)`
7. `payout_hash = Poseidon(payout_hi, payout_lo)`
8. `amount_1 + amount_2 == amount_t + fee`, `0 < amount_t < 2^64`

Constraint 6 is the note pool circuit's output commitment, unchanged. Constraint 7 is the credit note recipient binding, unchanged.

Change is not supported in a settle request. Use a transfer to split first if the notes do not sum to the desired payout. This keeps the settlement circuit small and keeps the queue free of change handling.

---

## 8. Note delivery

The recipient must learn `(blinding_o, rho_o, amount_o, expiry)` and, for their own bookkeeping, a memo. This is carried on chain, encrypted to the recipient's `epk`:

```
Sender:   ephemeral scalar r, ephemeral point R = r * B
          shared = r * epk                      (BabyJubJub ECDH)
          key    = Poseidon(shared.x, shared.y, DOMAIN_ENC)
          ciphertext = Encrypt(key, blinding_o || rho_o || amount_o || expiry || memo)
          post (R, ciphertext) with the transfer

Recipient: for each (R, ciphertext) on chain:
          shared = esk * R
          key    = Poseidon(shared.x, shared.y, DOMAIN_ENC)
          try Decrypt; on success, recompute out_inbox_leaf and confirm it was appended
```

`Encrypt` is an authenticated cipher chosen for the client, not the circuit; it runs off chain and is never proven. A sender who posts garbage only harms their own payment, which they can reclaim after expiry. This is the accepted trade-off in every shielded system that carries payloads on chain, and the reclaim path is what makes it a bounded loss here rather than a permanent one.

Scanning cost is one ECDH and one decryption attempt per transfer on chain. A light client can outsource trial decryption to a service by giving it the incoming viewing key, which cannot spend and cannot see outgoing activity.

**Gift notes carry no payload.** The claim code is the payload, delivered out of band, exactly as today.

---

## 9. Fees and relayers

A user with no public balance cannot pay for their own transaction. Two mechanisms, both without a trusted party:

- **In-proof fee.** The `fee` public input is subtracted inside the conservation constraint and credited to whoever produced the block. The producer is paid for including the transaction whether or not the sender has a public balance. This is the primary mechanism.
- **Relayers.** Any account may submit a proof on behalf of a sender and receive the fee. The relayer cannot alter the proof, redirect outputs, or learn anything the chain does not already reveal. Relayers are a convenience for network-level privacy, not a trust assumption.

Fees are quantized to a small set of tiers so the `fee` value carries at most a couple of bits of information.

---

## 10. Verifier interface

The chain, whatever its runtime, must implement:

```
state:
  wallet_tree, inbox_tree          incremental Poseidon Merkle trees, depth 20, root history >= 256
  wallet_nullifiers, inbox_nullifiers   insert-once sets
  settlement_queue                 map ticket -> (payout_hash, epoch or none)
  treasury                         public balance

primitives:
  poseidon(inputs[])               BN254 Poseidon, same parameters as circomlib
  groth16_verify(vk, proof, public_inputs[])   BN254
  current_epoch()

operations:
  shield(amount, inner)
  gift(amount, inner, expiry)
  transfer(proof, public_inputs, payload)
  claim(proof, public_inputs)
  reclaim(proof, public_inputs)
  settle_request(proof, public_inputs)
  settle_open(amount, blinding, salt)
  epoch_boundary()                 pays the current batch
```

Every check listed in section 6 is the verifier's responsibility. The circuits bind values; the verifier enforces uniqueness, time, and solvency.

**Solvency invariant.** At all times, `treasury >= sum of all unspent note amounts + sum of all unpaid tickets`. Since the verifier never learns note amounts, it cannot check this directly. It holds by induction: shield and gift add exactly what they receive, every proof conserves amounts minus a fee that is paid from the treasury in the same block, and every payout is an opened ticket that was created under conservation. The invariant is the reason the protocol has no admin sweep and no operator: there is nothing for an operator to do.

---

## 11. What is new here, and what is not

Being precise about this matters for review and for anyone evaluating the design.

**New in this protocol:**

- The offer, claim, reclaim life cycle for private transfers. Existing shielded systems make a sent note immediately spendable by the recipient and unrecoverable by the sender. Here a transfer is an offer with an expiry, refusable by inaction and recoverable by the sender, and the claim doubles as a private delivery receipt.
- The no-value-in-proof invariant applied to an entire ledger, with settlement batched per epoch so payout timing is uniform.
- The two-level leaf `Poseidon(Poseidon(pk, blinding, rho, tag), amount)` that lets the verifier build every leaf whose amount it can verify, extending the note pool's verified-leaf property to shield deposits.
- The inbox nullifier derived from `rho` alone so that claim and reclaim are mutually exclusive by construction rather than by a time-locked receipt record.

**Established techniques this protocol relies on:**

- Poseidon commitments and nullifiers, incremental Merkle trees with root history, and Groth16 over BN254, as in the existing circuits.
- Key-derived nullifiers for wallet notes (`Poseidon(nk, rho)`), so a note's creator cannot detect its spend. This is the Zcash Sapling construction.
- Two-input, two-output conservation with dummy inputs. Also Zcash.
- BabyJubJub ECDH for note encryption and trial-decryption scanning. Also Zcash.

Using established components where they fit is a strength, not a weakness. The novelty is in how the ledger is structured, and that is exactly the part that needs adversarial review before any deployment.

---

## 12. Security properties

| Property | Mechanism |
|----------|-----------|
| No value creation | Conservation constraint in transfer and settle circuits; shield and gift leaves built by the verifier from received amounts |
| No double spend | Insert-once wallet nullifier set; nullifier bound to `nk` and `rho` in-circuit |
| No double claim, no claim-and-reclaim | Insert-once inbox nullifier set shared by claim and reclaim |
| Only the addressee can claim | Claim circuit derives `pk` from `sk` and requires it to match the note |
| Only the creator can reclaim | Reclaim requires the full inbox preimage, held only by the sender and, encrypted, by the recipient |
| Sender cannot trace spends | Wallet nullifier needs `nk`; sender never has it |
| Sender cannot trace the claimed note | Claim output uses fresh `blinding_out`, `rho_out` |
| No payout without a ticket | Settlement opening must match a queued ticket created under conservation |
| Payout goes to the intended account | `payout_hash` binding, as in the credit note withdraw |
| Timing decorrelation at exit | Epoch batching with content-derived payout order |
| Treasury solvency | Induction over the operations, section 10 |

---

## 13. Known limitations

1. **Shield and payout are public.** Amounts entering and leaving are visible. Privacy is over what happens between them. Users who need to hide totals should shield in standard sizes and settle in standard sizes.
2. **The delivery receipt is a leak.** The sender learns when their offer was claimed. This is a design choice; it can be removed by deriving the inbox nullifier from the recipient's `nk`, at the cost of the reclaim path. That trade-off should be revisited if reclaim turns out to be little used.
3. **Expiry is public at claim time.** It is quantized to epochs, and the allowed window is fixed, so it reveals at most which epoch the offer was created in. Senders should use the default expiry unless they have a reason not to.
4. **Fee tiers are visible.** Bounded to a few bits.
5. **Anonymity set is the tree.** As in every commitment-based system, privacy grows with use. The inbox tree and the wallet tree each have their own set.
6. **Trusted setup.** Groth16 needs a multi-party ceremony per circuit before mainnet. Four circuits, four ceremonies, or one universal-setup proof system. See open questions.
7. **Unproven encryption.** A sender can post a payload the recipient cannot decrypt. The sender can reclaim after expiry, so the loss is temporary, but the recipient is not notified.

---

## 14. Open questions

1. **Runtime.** This spec is runtime-neutral. The verifier interface in section 10 is small enough to implement as a native module of a purpose-built chain, which is the natural home for a protocol whose block producer is a party to every transfer's fee. A decision is needed before implementation starts.
2. **Proof system.** Groth16 on BN254 keeps continuity with the audited circuits and the cheapest verification. A universal-setup system removes the per-circuit ceremony. The circuits in this spec are written so that either works.
3. **Epoch length.** Drives settlement latency, expiry granularity, and batch anonymity. Needs a number.
4. **Default expiry and allowed window.** Proposed: default 30 epochs, window 1 to 365.
5. **Fee tiers.** Proposed: four tiers.
6. **Change to first input's owner.** Fixed in the transfer circuit for simplicity. A transfer that merges notes from two of your own addresses sends change to the first. Acceptable?
7. **Assets.** This draft is single-asset. Adding an `asset` field to `inner` and a per-asset conservation constraint is straightforward and should be decided before the circuits are written, because it changes every leaf.
8. **Public-key encryption on BabyJubJub versus a second key type.** BabyJubJub keeps every key derivable from `sk` with Poseidon. A client that wants hardware-wallet support may prefer a curve the hardware already speaks.

---

## 15. Implementation order

1. Write the four circuits in circom, reusing `lib/merkle_tree.circom` and the existing Poseidon patterns. Test each statement with the same style of suite as `circuits/test/darkdrop.test.js`, including every negative case in section 12.
2. Write a reference verifier in TypeScript against the interface in section 10, with an in-memory state, so the full life cycle can be exercised end to end before any chain exists.
3. Write the client library: key derivation, address encoding, note construction, payload encryption, scanning, proof generation.
4. Choose the runtime and port the reference verifier.
5. Ceremony, audit, deploy.

Step 2 is the point at which this design either holds together or does not, and it costs nothing but time. Do it before choosing a runtime.
