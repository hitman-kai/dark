use anchor_lang::prelude::*;
use anchor_spl::token::Mint;
use crate::state::*;
use crate::errors::DarkDropError;
use crate::verifier::verify_proof_v2;
use crate::poseidon::{poseidon_hash, pubkey_to_field};

/// SPL parallel of `claim_credit` for SOL. Verify a V2 ZK proof, mint a
/// per-mint nullifier (double-claim guard), and issue a re-randomized
/// CreditNoteSpl that the recipient (or someone they share with) later
/// withdraws against via `withdraw_credit_spl`.
///
/// Structurally mirrors `claim_credit.rs`. Same V2 verifier, same 4
/// public inputs in the same order, same `pubkey_to_field` recipient
/// hashing, same `Poseidon(commitment, salt)` re-randomization
/// (M-01-NEW fix), same global `Vault.total_claims` bump.
///
/// Differences from SOL flow:
///   1. Reads root from the per-mint `MerkleTreeSpl` instead of the
///      shared `MerkleTreeAccount`.
///   2. Nullifier PDA in the per-mint namespace
///      `[b"nullifier_spl", mint, nullifier_hash]` — disjoint from the
///      SOL nullifier namespace so SOL and SPL claims with a
///      hypothetically-colliding hash never interact.
///   3. CreditNoteSpl PDA at `[b"credit_spl", mint, nullifier_hash]`,
///      and the stored record carries `mint` so `withdraw_credit_spl`
///      can later locate the right mint vault.
///
/// ZERO TOKEN MOVEMENT in this instruction — same as the SOL flow.
/// The amount is a private input in the ZK proof; only the Poseidon
/// commitment is stored.
///
/// The `inputs` parameter is the same opaque 64-byte vector as the SOL
/// path (issue #20: the former [64..96] password_hash was removed):
///   [0..32]  merkle_root
///   [32..64] amount_commitment
pub fn handle_claim_credit_spl(
    ctx: Context<ClaimCreditSpl>,
    nullifier_hash: [u8; 32],
    proof: ProofData,
    inputs: Vec<u8>,
    salt: [u8; 32],
) -> Result<()> {
    // Parse opaque inputs — same layout as claim_credit.rs.
    // (issue #20: password_hash removed, 96 -> 64 bytes)
    require!(inputs.len() == 64, DarkDropError::InvalidInputLength);

    let merkle_root: [u8; 32] = inputs[0..32].try_into().unwrap();
    let amount_commitment: [u8; 32] = inputs[32..64].try_into().unwrap();

    // Validate merkle root against the per-mint tree's root history.
    let tree = ctx.accounts.merkle_tree_spl.load()?;
    require!(
        tree.is_known_root(&merkle_root),
        DarkDropError::InvalidRoot
    );
    drop(tree);

    // Recipient field element — Poseidon(hi_128, lo_128). Same encoding
    // as the SOL `pubkey_to_field` so SPL claims share the recipient
    // binding semantics; the function is duplicated locally so this
    // file does not depend on internal items of claim_credit.rs (which
    // is audited code we choose not to touch).
    let recipient_hash = pubkey_to_field(&ctx.accounts.recipient.key());

    // Public inputs — 4 elements, same order as V2 verifier expects.
    let public_inputs: [[u8; 32]; 4] = [
        merkle_root,
        nullifier_hash,
        recipient_hash,
        amount_commitment,
    ];

    verify_proof_v2(&proof, &public_inputs)?;

    // Re-randomize the commitment before storing. M-01-NEW fix on the
    // SOL flow; same purpose here — prevents an indexer from matching
    // a CreditNoteSpl.commitment back to the deposit-time
    // amount_commitment, which would re-link claim to deposit.
    let stored_commitment = poseidon_hash(&amount_commitment, &salt);

    let credit = &mut ctx.accounts.credit_note_spl;
    credit.bump = ctx.bumps.credit_note_spl;
    credit.recipient = ctx.accounts.recipient.key();
    credit.commitment = stored_commitment;
    credit.nullifier_hash = nullifier_hash;
    credit.salt = salt;
    credit.created_at = Clock::get()?.unix_timestamp;
    credit.mint = ctx.accounts.mint.key();

    // Existence of the nullifier PDA = nullifier spent. Anchor `init`
    // gives mutual exclusion for free.
    ctx.accounts.nullifier_account_spl.nullifier_hash = nullifier_hash;

    // Global cross-asset claim counter — same as SOL flow at
    // claim_credit.rs:78-81.
    let vault = &mut ctx.accounts.vault;
    vault.total_claims = vault.total_claims
        .checked_add(1)
        .ok_or(DarkDropError::Overflow)?;

    emit!(CreditCreatedSpl {
        mint: ctx.accounts.mint.key(),
        nullifier_hash,
        recipient: ctx.accounts.recipient.key(),
        timestamp: credit.created_at,
    });

    // NO TOKEN TRANSFER. NO AMOUNT IN INSTRUCTION DATA OR EVENTS.
    // Commitment deliberately omitted from the event to keep
    // deposit↔claim linkage broken at the indexer layer.

    Ok(())
}

#[derive(Accounts)]
#[instruction(nullifier_hash: [u8; 32])]
pub struct ClaimCreditSpl<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [b"mint_config", mint.key().as_ref()],
        bump = mint_config.bump,
        has_one = mint,
    )]
    pub mint_config: Account<'info, MintConfig>,

    #[account(
        seeds = [b"merkle_tree_spl", mint.key().as_ref()],
        bump,
    )]
    pub merkle_tree_spl: AccountLoader<'info, MerkleTreeSpl>,

    /// Nullifier PDA — double-claim prevention. Per-mint namespace.
    #[account(
        init,
        payer = payer,
        space = NullifierAccountSpl::SIZE,
        seeds = [b"nullifier_spl", mint.key().as_ref(), nullifier_hash.as_ref()],
        bump,
    )]
    pub nullifier_account_spl: Account<'info, NullifierAccountSpl>,

    /// CreditNoteSpl PDA — wider record that carries the source mint.
    #[account(
        init,
        payer = payer,
        space = CreditNoteSpl::SIZE,
        seeds = [b"credit_spl", mint.key().as_ref(), nullifier_hash.as_ref()],
        bump,
    )]
    pub credit_note_spl: Account<'info, CreditNoteSpl>,

    pub mint: Account<'info, Mint>,

    /// CHECK: Recipient — any account, NOT a signer.
    /// Bound by the ZK proof via Poseidon(pubkey).
    pub recipient: UncheckedAccount<'info>,

    /// Fee payer (relayer in gasless mode, claimer in direct mode).
    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct CreditCreatedSpl {
    pub mint: Pubkey,
    pub nullifier_hash: [u8; 32],
    pub recipient: Pubkey,
    pub timestamp: i64,
}
