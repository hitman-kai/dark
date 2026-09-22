use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};
use crate::state::*;
use crate::errors::DarkDropError;

/// Create the program-owned SPL token account that holds custody of a
/// registered mint's deposits.
///
/// Preconditions:
///   - `initialize_mint_config` has run (the MintConfig PDA exists).
///   - `initialize_mint_trees` has run (the main + pool tree pubkeys on
///     MintConfig are no longer `Pubkey::default()`).
///
/// The mint vault is a PDA-derived TokenAccount whose authority is the
/// shared Vault PDA — only this program can move tokens out, signing with
/// `[b"vault"]` seeds.
///
/// After this runs, MintConfig.mint_vault carries the token account
/// pubkey and the mint is fully provisioned for SPL deposits / claims.
pub fn handle_initialize_mint_vault(ctx: Context<InitializeMintVault>) -> Result<()> {
    let mint_config = &mut ctx.accounts.mint_config;

    // Trees-must-be-initialized precondition. We surface a clear error
    // instead of relying on downstream instructions to discover the gap.
    // Using `MintNotRegistered` per the spec — semantically "the mint isn't
    // fully registered yet, complete the registration sequence first."
    require!(
        mint_config.merkle_tree != Pubkey::default(),
        DarkDropError::MintNotRegistered
    );
    require!(
        mint_config.note_pool_tree != Pubkey::default(),
        DarkDropError::MintNotRegistered
    );

    mint_config.mint_vault = ctx.accounts.mint_vault.key();

    msg!(
        "MintVault initialized for mint {} at {}",
        ctx.accounts.mint.key(),
        mint_config.mint_vault
    );
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeMintVault<'info> {
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

    #[account(
        init,
        payer = authority,
        seeds = [b"mint_vault", mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = vault,
    )]
    pub mint_vault: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}
