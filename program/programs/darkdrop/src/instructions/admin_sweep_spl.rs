use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use crate::state::*;
use crate::errors::DarkDropError;

/// Admin sweep for a registered SPL mint. Transfers excess tokens from
/// the program-owned mint vault to an admin-chosen destination ATA,
/// subject to the user-owed floor invariant:
///
///     outstanding   = mint_config.total_deposited - mint_config.total_withdrawn
///     max_sweepable = mint_vault.amount - outstanding
///     require(amount <= max_sweepable)
///
/// This is the most safety-critical SPL instruction in the surface:
/// a bug here lets the admin drain user deposits. The floor math is
/// structured so any deviation (off-by-one, overflow, signed math)
/// produces a hard error rather than a silent over-sweep.
///
/// Mirrors `admin_sweep.rs` for the SOL flow with three concrete
/// differences:
///   1. SPL `token::transfer` CPI instead of direct lamport
///      manipulation. Vault PDA signs as the mint_vault's authority
///      with `[b"vault", &[bump]]` signer seeds.
///   2. No rent-exempt-minimum subtraction. The TokenAccount's SOL
///      rent is independent of its token balance, so it never needs
///      to be reserved out of the swept amount.
///   3. Accepts an explicit `amount: u64` parameter rather than
///      auto-sweeping all excess. Partial sweeps are useful when the
///      admin wants to leave headroom for slippage / future
///      reconciliation; the audited SOL ix sweeps everything at once.
///      The floor invariant is checked the same way — only the upper
///      bound is admin-chosen.
///
/// MintConfig.total_deposited and total_withdrawn are NOT modified.
/// Those counters track user deposits and user withdrawals; admin
/// sweep is a separate book. Modifying them would corrupt the floor
/// math for subsequent sweeps and would let the admin tamper with the
/// invariant after the fact.
pub fn handle_admin_sweep_spl(
    ctx: Context<AdminSweepSpl>,
    amount: u64,
) -> Result<()> {
    require!(amount > 0, DarkDropError::ZeroAmount);

    let mint_config = &ctx.accounts.mint_config;
    let outstanding = mint_config
        .total_deposited
        .checked_sub(mint_config.total_withdrawn)
        .ok_or(DarkDropError::Overflow)?;

    let max_sweepable = ctx
        .accounts
        .mint_vault
        .amount
        .checked_sub(outstanding)
        .ok_or(DarkDropError::InsufficientBalance)?;

    require!(amount <= max_sweepable, DarkDropError::InsufficientBalance);

    // Vault PDA signs the outbound transfer — same pattern as
    // withdraw_credit_spl. Mint vault's authority was set to the Vault
    // PDA at initialize_mint_vault time.
    let vault_bump = ctx.accounts.vault.bump;
    let vault_seeds: &[&[u8]] = &[b"vault", core::slice::from_ref(&vault_bump)];
    let signer_seeds: &[&[&[u8]]] = &[vault_seeds];

    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.mint_vault.to_account_info(),
                to: ctx.accounts.destination_ata.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
            signer_seeds,
        ),
        amount,
    )?;

    emit!(MintVaultSwept {
        mint: ctx.accounts.mint.key(),
        authority: ctx.accounts.authority.key(),
        amount,
        timestamp: Clock::get()?.unix_timestamp,
    });

    msg!(
        "Swept {} base units of mint {} (floor preserved: {} >= {})",
        amount,
        ctx.accounts.mint.key(),
        max_sweepable.saturating_sub(amount),
        0u64
    );
    Ok(())
}

#[derive(Accounts)]
pub struct AdminSweepSpl<'info> {
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,

    /// MintConfig is read-only here — the floor counters MUST NOT be
    /// touched by sweep. Cross-mint mismatch is caught by
    /// `has_one = mint_vault` (defense in depth alongside the seeds).
    #[account(
        seeds = [b"mint_config", mint.key().as_ref()],
        bump = mint_config.bump,
        has_one = mint,
        has_one = mint_vault,
    )]
    pub mint_config: Account<'info, MintConfig>,

    #[account(
        mut,
        seeds = [b"mint_vault", mint.key().as_ref()],
        bump,
    )]
    pub mint_vault: Account<'info, TokenAccount>,

    /// Admin-chosen destination. Only the mint is constrained — the
    /// admin is trusted to pick the right ATA (e.g., a multisig
    /// treasury). Tightening to `authority`-owned is gratuitous given
    /// the admin already controls the sweep.
    #[account(
        mut,
        token::mint = mint,
    )]
    pub destination_ata: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[event]
pub struct MintVaultSwept {
    pub mint: Pubkey,
    pub authority: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}
