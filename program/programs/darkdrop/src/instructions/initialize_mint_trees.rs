use anchor_lang::prelude::*;
use anchor_spl::token::Mint;
use crate::state::*;

/// Initialize the per-mint main Merkle tree and note pool tree for a mint
/// that's already been registered via `initialize_mint_config`.
///
/// Mirrors the SOL-side `initialize_vault` (main tree zero-init) and
/// `initialize_note_pool` (note pool zero-init) patterns. After this runs,
/// the MintConfig record carries the addresses of both per-mint trees so
/// downstream SPL instructions can locate them without re-deriving from
/// scratch each call.
///
/// Authority-gated via `has_one = authority` on the Vault PDA.
/// Mint↔config binding via `has_one = mint` on MintConfig.
pub fn handle_initialize_mint_trees(ctx: Context<InitializeMintTrees>) -> Result<()> {
    // Main tree zero-init — identical pattern to initialize_vault.rs.
    let merkle_tree = &mut ctx.accounts.merkle_tree_spl.load_init()?;
    merkle_tree.vault = ctx.accounts.vault.key();
    merkle_tree.mint = ctx.accounts.mint.key();
    merkle_tree.next_index = 0;
    merkle_tree.root_history_index = 0;

    for i in 0..MERKLE_DEPTH {
        merkle_tree.filled_subtrees[i] = ZERO_HASHES[i];
    }

    merkle_tree.current_root = ZERO_HASHES[MERKLE_DEPTH];

    // Seed every root_history slot with the empty-tree root, matching the
    // Audit 03 L-03-NEW / Audit 04 L-01 fix on the SOL trees so SPL trees
    // inherit the same property.
    for i in 0..ROOT_HISTORY_SIZE {
        merkle_tree.root_history[i] = ZERO_HASHES[MERKLE_DEPTH];
    }

    // Note pool tree zero-init — same shape.
    let pool_tree = &mut ctx.accounts.note_pool_tree_spl.load_init()?;
    pool_tree.vault = ctx.accounts.vault.key();
    pool_tree.mint = ctx.accounts.mint.key();
    pool_tree.next_index = 0;
    pool_tree.root_history_index = 0;

    for i in 0..MERKLE_DEPTH {
        pool_tree.filled_subtrees[i] = ZERO_HASHES[i];
    }

    pool_tree.current_root = ZERO_HASHES[MERKLE_DEPTH];

    for i in 0..ROOT_HISTORY_SIZE {
        pool_tree.root_history[i] = ZERO_HASHES[MERKLE_DEPTH];
    }

    // Cache tree addresses on the MintConfig. mint_vault stays at default
    // — that's set later by initialize_mint_vault.
    let mint_config = &mut ctx.accounts.mint_config;
    mint_config.merkle_tree = ctx.accounts.merkle_tree_spl.key();
    mint_config.note_pool_tree = ctx.accounts.note_pool_tree_spl.key();

    msg!(
        "MintTrees initialized for mint {} — main {}, pool {}",
        ctx.accounts.mint.key(),
        mint_config.merkle_tree,
        mint_config.note_pool_tree
    );
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeMintTrees<'info> {
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
        space = 8 + std::mem::size_of::<MerkleTreeSpl>(),
        seeds = [b"merkle_tree_spl", mint.key().as_ref()],
        bump,
    )]
    /// CHECK: Initialized as zero_copy account.
    pub merkle_tree_spl: AccountLoader<'info, MerkleTreeSpl>,

    #[account(
        init,
        payer = authority,
        space = 8 + std::mem::size_of::<NotePoolTreeSpl>(),
        seeds = [b"note_pool_tree_spl", mint.key().as_ref()],
        bump,
    )]
    /// CHECK: Initialized as zero_copy account.
    pub note_pool_tree_spl: AccountLoader<'info, NotePoolTreeSpl>,

    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}
