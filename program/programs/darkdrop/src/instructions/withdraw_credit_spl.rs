use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use crate::state::*;
use crate::errors::DarkDropError;
use crate::poseidon::{poseidon_hash, u64_to_field_be};

/// SPL parallel of `withdraw_credit` for SOL. Open the Poseidon
/// commitment stored on a CreditNoteSpl, transfer SPL tokens from the
/// program-owned mint vault to the recipient ATA, and close the credit
/// note (rent refund to payer).
///
/// Structurally mirrors `withdraw_credit.rs`. Same 72-byte opening
/// layout, same nested-Poseidon re-randomization recompute, same
/// `rate` basis-points fee model with 500 bps cap, same
/// `close = payer` rent flow. Like the SOL path, the salt is checked
/// against the authoritative on-chain `credit_note_spl.salt` first and
/// falls back to the caller-supplied salt for note-pool notes whose
/// stored salt is a decoy (Audit 06 M-02 parity — see withdraw_credit.rs).
///
/// Differences from SOL flow:
///   1. SPL `token::transfer` CPI instead of direct lamport manipulation.
///      The audited "no decoded Transfer inner instruction" property is
///      a SOL-only outcome of direct-lamport debits on the Treasury PDA.
///      For SPL, the inner Transfer instruction is unavoidable —
///      moving SPL tokens always goes through the Token program. This
///      makes the withdraw amount slightly more indexer-visible for
///      SPL than for SOL, which is documented in the design memo
///      §4.1 as expected.
///   2. Per-mint accounting on `MintConfig.total_withdrawn` (in token
///      base units) instead of `Vault.total_withdrawn` (lamports).
///   3. Vault PDA signs the `token::transfer` CPI as the mint_vault's
///      authority, using `[b"vault", &[bump]]` signer seeds.
///
/// Opening byte layout (matches SOL):
///   [0..8]   amount (u64 little-endian)
///   [8..40]  blinding factor (32 bytes)
///   [40..72] salt (32 bytes) — caller-supplied; fallback for pool notes
///
/// Salt handling mirrors withdraw_credit.rs (Audit 06 M-02): try the
/// authoritative on-chain `credit_note_spl.salt` first, fall back to the
/// caller-supplied salt for note-pool notes whose stored salt is a decoy.
pub fn handle_withdraw_credit_spl(
    ctx: Context<WithdrawCreditSpl>,
    _nullifier_hash: [u8; 32],
    opening: Vec<u8>,
    rate: u16,
) -> Result<()> {
    require!(opening.len() == 72, DarkDropError::InvalidInputLength);

    let amount = u64::from_le_bytes(opening[0..8].try_into().unwrap());
    let blinding_factor: [u8; 32] = opening[8..40].try_into().unwrap();
    let caller_salt: [u8; 32] = opening[40..72].try_into().unwrap();

    let credit = &ctx.accounts.credit_note_spl;

    // Recompute the re-randomized commitment. Try authoritative credit.salt
    // first, then the caller-supplied salt (pool-note decoy fallback).
    // See withdraw_credit.rs for the full rationale (Audit 06 M-02).
    let amount_bytes = u64_to_field_be(amount);
    let original_commitment = poseidon_hash(&amount_bytes, &blinding_factor);
    let matches_stored =
        poseidon_hash(&original_commitment, &credit.salt) == credit.commitment;
    let matches_caller =
        poseidon_hash(&original_commitment, &caller_salt) == credit.commitment;
    require!(
        matches_stored || matches_caller,
        DarkDropError::CommitmentMismatch
    );

    require!(amount > 0, DarkDropError::ZeroAmount);

    // Same 500 bps fee cap as the SOL flow.
    const MAX_FEE_RATE: u16 = 500;
    require!(rate <= MAX_FEE_RATE, DarkDropError::FeeTooHigh);

    let fee = if rate > 0 {
        (amount as u128)
            .checked_mul(rate as u128)
            .ok_or(DarkDropError::Overflow)?
            .checked_div(10000)
            .ok_or(DarkDropError::Overflow)? as u64
    } else {
        0u64
    };

    let recipient_amount = amount.checked_sub(fee).ok_or(DarkDropError::Overflow)?;

    // Solvency check on the mint vault. No rent-exempt subtraction needed:
    // the TokenAccount's SOL rent is independent of its token balance.
    require!(
        ctx.accounts.mint_vault.amount >= amount,
        DarkDropError::InsufficientBalance
    );

    // Vault PDA is the authority of `mint_vault` (set at
    // initialize_mint_vault time via `token::authority = vault`).
    // Sign the SPL transfer CPI with the vault seeds.
    let vault_bump = ctx.accounts.vault.bump;
    let vault_seeds: &[&[u8]] = &[b"vault", core::slice::from_ref(&vault_bump)];
    let signer_seeds: &[&[&[u8]]] = &[vault_seeds];

    // Recipient transfer (the net, post-fee amount).
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.mint_vault.to_account_info(),
                to: ctx.accounts.recipient_ata.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
            signer_seeds,
        ),
        recipient_amount,
    )?;

    // Fee transfer to payer (relayer in gasless mode). Conditional —
    // direct-mode users pass rate=0 and avoid the second CPI entirely.
    if fee > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.mint_vault.to_account_info(),
                    to: ctx.accounts.payer_ata.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                signer_seeds,
            ),
            fee,
        )?;
    }

    // Per-mint withdrawn counter — mirrors create_drop_spl on the deposit
    // side. Global Vault.total_withdrawn stays lamport-only.
    let mint_config = &mut ctx.accounts.mint_config;
    mint_config.total_withdrawn = mint_config.total_withdrawn
        .checked_add(amount)
        .ok_or(DarkDropError::Overflow)?;

    emit!(CreditWithdrawnSpl {
        mint: ctx.accounts.mint.key(),
        nullifier_hash: credit.nullifier_hash,
        recipient: credit.recipient,
        timestamp: Clock::get()?.unix_timestamp,
    });

    // CreditNoteSpl PDA closed by `close = payer` constraint on the
    // account. Rent refund flows to the payer (gasless: relayer; direct:
    // user). No amount in instruction data, no amount in events.

    Ok(())
}

#[derive(Accounts)]
#[instruction(nullifier_hash: [u8; 32])]
pub struct WithdrawCreditSpl<'info> {
    /// Vault — read-only here. Loaded so we can read `vault.bump` for
    /// the `token::transfer` signer seeds and so the seeds constraint
    /// pins the well-known address.
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    /// MintConfig — mut for the per-mint `total_withdrawn` bump. The
    /// `has_one = mint_vault` constraint defends against a swap of
    /// `mint_vault` for a different mint's vault.
    #[account(
        mut,
        seeds = [b"mint_config", mint.key().as_ref()],
        bump = mint_config.bump,
        has_one = mint,
        has_one = mint_vault,
    )]
    pub mint_config: Account<'info, MintConfig>,

    /// CreditNoteSpl — closed after withdrawal; rent refunded to payer.
    /// Anchor enforces the PDA seeds and mint-binding via the seed.
    #[account(
        mut,
        seeds = [b"credit_spl", mint.key().as_ref(), nullifier_hash.as_ref()],
        bump = credit_note_spl.bump,
        close = payer,
        constraint = credit_note_spl.mint == mint.key() @ DarkDropError::WrongMint,
    )]
    pub credit_note_spl: Account<'info, CreditNoteSpl>,

    /// Program-owned token custody. Vault PDA signs the outbound transfer.
    #[account(
        mut,
        seeds = [b"mint_vault", mint.key().as_ref()],
        bump,
    )]
    pub mint_vault: Account<'info, TokenAccount>,

    /// Recipient ATA. Owner is bound to `credit_note_spl.recipient` —
    /// the same recipient pubkey that was committed inside the V2 ZK
    /// proof at claim time. Mint binding is via `token::mint`.
    #[account(
        mut,
        token::mint = mint,
        constraint = recipient_ata.owner == credit_note_spl.recipient
            @ DarkDropError::UnauthorizedWithdraw,
    )]
    pub recipient_ata: Account<'info, TokenAccount>,

    /// Payer ATA — receives the relayer fee in source-mint base units.
    /// Owned by `payer`. In direct mode (rate=0) this account is parsed
    /// and validated but never written to.
    #[account(
        mut,
        token::mint = mint,
        token::authority = payer,
    )]
    pub payer_ata: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    /// Fee payer + rent destination. Relayer in gasless mode, claimer
    /// in direct mode.
    #[account(mut)]
    pub payer: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct CreditWithdrawnSpl {
    pub mint: Pubkey,
    pub nullifier_hash: [u8; 32],
    pub recipient: Pubkey,
    pub timestamp: i64,
}
