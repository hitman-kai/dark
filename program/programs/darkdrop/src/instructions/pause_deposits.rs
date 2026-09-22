use anchor_lang::prelude::*;
use anchor_spl::token::Mint;
use crate::state::*;

/// Pause or unpause new deposits for a registered mint.
///
/// Sets `MintConfig.paused = paused`. When true, subsequent
/// `create_drop_spl` calls for this mint fail with `MintPaused`.
/// Outstanding credit notes remain withdrawable regardless — the
/// kill-switch only closes the deposit side, so users always have a
/// path to exit even for a paused mint.
///
/// `paused` is passed as an explicit boolean rather than as a toggle.
/// Toggling-by-current-state would race when two admin TXs are in
/// flight; the explicit-target form is idempotent and leaves the
/// post-state unambiguous from the instruction data alone.
///
/// Authority-gated via `has_one = authority` on the shared Vault PDA.
/// No SOL parallel — the SOL flow has no per-mint kill switch
/// (only the global `vault.drop_cap`).
pub fn handle_pause_deposits(
    ctx: Context<PauseDeposits>,
    paused: bool,
) -> Result<()> {
    ctx.accounts.mint_config.paused = paused;

    emit!(MintPauseChanged {
        mint: ctx.accounts.mint.key(),
        paused,
        timestamp: Clock::get()?.unix_timestamp,
    });

    msg!(
        "Mint {} pause set to {}",
        ctx.accounts.mint.key(),
        paused
    );
    Ok(())
}

#[derive(Accounts)]
pub struct PauseDeposits<'info> {
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"mint_config", mint.key().as_ref()],
        bump = mint_config.bump,
        has_one = mint,
    )]
    pub mint_config: Account<'info, MintConfig>,

    pub mint: Account<'info, Mint>,

    pub authority: Signer<'info>,
}

#[event]
pub struct MintPauseChanged {
    pub mint: Pubkey,
    pub paused: bool,
    pub timestamp: i64,
}
