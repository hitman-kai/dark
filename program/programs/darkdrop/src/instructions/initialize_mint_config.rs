use anchor_lang::prelude::*;
use anchor_spl::token::Mint;
use crate::state::*;

/// Register a new SPL mint with the program.
///
/// Creates a `MintConfig` PDA keyed by the mint. Tree, note-pool tree, and
/// mint-vault pubkeys are placeholders (`Pubkey::default()`) — they are set
/// by a later instruction so this one stays small and easy to audit.
///
/// Authority-gated via `has_one = authority` on the Vault PDA.
pub fn handle_initialize_mint_config(ctx: Context<InitializeMintConfig>) -> Result<()> {
    let mint_config = &mut ctx.accounts.mint_config;
    mint_config.bump = ctx.bumps.mint_config;
    mint_config.mint = ctx.accounts.mint.key();
    mint_config.registered_at = Clock::get()?.unix_timestamp;
    mint_config.merkle_tree = Pubkey::default();
    mint_config.note_pool_tree = Pubkey::default();
    mint_config.mint_vault = Pubkey::default();
    mint_config.total_deposited = 0;
    mint_config.total_withdrawn = 0;
    mint_config.paused = false;

    msg!("MintConfig registered for mint {}", mint_config.mint);
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeMintConfig<'info> {
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init,
        payer = authority,
        space = MintConfig::SIZE,
        seeds = [b"mint_config", mint.key().as_ref()],
        bump,
    )]
    pub mint_config: Account<'info, MintConfig>,

    // Audit 06 M-04: this `Account<'info, Mint>` binding is LEGACY SPL Token
    // only (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA), and that is a
    // deliberate scope decision — Token-2022 is explicitly NOT supported. A
    // Token-2022 mint fails here at Anchor account deserialization with
    // `AccountOwnedByWrongProgram` (the owner is the Token-2022 program, not the
    // legacy program). That error is non-obvious to integrators, so the binding
    // and its rationale are documented in ARCHITECTURE.md ("Token program
    // binding / Token-2022 scope"). Supporting Token-2022 is a separate
    // design-and-audit effort: it requires `token_interface` types AND explicit
    // transfer-fee accounting on every ingress path, because the
    // `TransferFeeConfig` extension would otherwise let a pool leaf commit to a
    // pre-fee amount the vault never receives (a dishonest-leaf reintroduction).
    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}
