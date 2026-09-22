use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use crate::state::*;
use crate::errors::DarkDropError;
use crate::poseidon::{poseidon_hash, poseidon_hash_4, u64_to_field_be};

/// SPL parallel of `create_drop_to_pool`. Single-TX deposit of SPL tokens
/// directly into the per-mint Note Pool layer, skipping the main tree.
///
/// Privacy: depositor's wallet is linked on-chain to a pool leaf only.
/// The V3 circuit hides the pool-leaf → recipient link at claim time, so
/// an observer learns (depositor, mint, amount) but not (depositor,
/// recipient). Same privacy property as the SOL flow.
///
/// No dishonest-leaf risk (Audit I-01): `amount` is the value actually
/// transferred via the SPL CPI. The pool leaf is constructed on-chain
/// using that verified amount — there is no commitment-scheme opening
/// that could lie about the value.
///
/// `pool_params` is opaque bytes (96 total) — same layout as SOL:
///   [0..32]  pool_secret
///   [32..64] pool_nullifier
///   [64..96] pool_blinding
///
/// Differences from SOL flow:
///   1. SPL `token::transfer` CPI instead of `system_program::transfer`.
///   2. Pool leaf appended to the per-mint `NotePoolTreeSpl` instead of
///      the singleton `NotePoolTree`. Merkle algorithm inlined locally
///      to avoid touching the audited `note_pool_tree_append` in
///      merkle_tree.rs — same approach as `create_drop_spl`.
///   3. New `require!(!mint_config.paused, MintPaused)` gate. The SPL
///      kill switch closes pool deposits too — pause is per-mint and
///      covers every entrypoint that mints new SPL obligations.
///   4. Per-mint volume on `MintConfig.total_deposited` (covers both
///      main-tree and pool-tree deposits — admin_sweep_spl's floor
///      reads the same counter, so pool funds are correctly reserved).
///   5. No `note_pool.total_deposits` bump. The SOL singleton
///      `NotePool` account has no SPL equivalent; we don't introduce a
///      `NotePoolSpl` singleton here because nothing reads from it yet
///      (pool-side accounting can live on MintConfig + the tree's
///      `next_index` for now).
pub fn handle_create_drop_to_pool_spl(
    ctx: Context<CreateDropToPoolSpl>,
    amount: u64,
    pool_params: Vec<u8>,
) -> Result<()> {
    // 1. Amount validation — same envelope as create_drop_spl /
    // create_drop. drop_cap and MIN_DEPOSIT_LAMPORTS reused as raw
    // base-unit thresholds; see create_drop_spl module comment.
    require!(amount >= MIN_DEPOSIT_LAMPORTS, DarkDropError::BelowMinDeposit);
    require!(
        amount <= ctx.accounts.vault.drop_cap,
        DarkDropError::AmountExceedsCap
    );

    // 2. Pause check — closes pool deposits when the mint is in
    // kill-switch state. Outstanding pool credits remain claimable.
    require!(
        !ctx.accounts.mint_config.paused,
        DarkDropError::MintPaused
    );

    // 3. Pool preimage parsing — same 96-byte layout as SOL.
    require!(pool_params.len() == 96, DarkDropError::InvalidInputLength);
    let pool_secret: [u8; 32] = pool_params[0..32].try_into().unwrap();
    let pool_nullifier: [u8; 32] = pool_params[32..64].try_into().unwrap();
    let pool_blinding: [u8; 32] = pool_params[64..96].try_into().unwrap();

    // 4. SPL transfer user_ata → mint_vault. Equivalent of SOL's
    // system_program::transfer to the treasury PDA.
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.user_ata.to_account_info(),
                to: ctx.accounts.mint_vault.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        ),
        amount,
    )?;

    // 5. Construct pool leaf with the verified amount. Matches the V3
    // circuit's leaf hash: Poseidon(secret, nullifier, amount, blinding).
    let amount_bytes = u64_to_field_be(amount);
    let pool_leaf = poseidon_hash_4(&pool_secret, &pool_nullifier, &amount_bytes, &pool_blinding);

    // 6. Append pool_leaf to the per-mint pool tree. Algorithm IDENTICAL
    // to `note_pool_tree_append` in merkle_tree.rs — inlined here so we
    // don't modify the audited file. Same RefMut two-phase-borrow
    // workaround as create_drop_spl (extract new_root_idx into a local).
    let leaf_index;
    let pool_root;
    {
        let tree = &mut ctx.accounts.note_pool_tree_spl.load_mut()?;
        let max_capacity = 1u32 << MERKLE_DEPTH;
        require!(tree.next_index < max_capacity, DarkDropError::TreeFull);

        leaf_index = tree.next_index;
        let mut current_index = tree.next_index as usize;
        let mut current_level_hash = pool_leaf;
        for i in 0..MERKLE_DEPTH {
            let (left, right) = if current_index % 2 == 0 {
                tree.filled_subtrees[i] = current_level_hash;
                (current_level_hash, ZERO_HASHES[i])
            } else {
                (tree.filled_subtrees[i], current_level_hash)
            };
            current_level_hash = poseidon_hash(&left, &right);
            current_index /= 2;
        }
        tree.current_root = current_level_hash;
        let new_root_idx =
            (tree.root_history_index + 1) % ROOT_HISTORY_SIZE as u32;
        tree.root_history_index = new_root_idx;
        tree.root_history[new_root_idx as usize] = current_level_hash;
        tree.next_index = tree.next_index
            .checked_add(1)
            .ok_or(DarkDropError::Overflow)?;
        pool_root = tree.current_root;
    }

    // 7. Counter updates. Per-mint volume covers BOTH main-tree and
    // pool-tree deposits (admin_sweep_spl floor reads the same counter,
    // so pool funds are reserved alongside main-tree funds). Global
    // drop count bumps in lock-step with create_drop / create_drop_spl.
    {
        let mint_config = &mut ctx.accounts.mint_config;
        mint_config.total_deposited = mint_config.total_deposited
            .checked_add(amount)
            .ok_or(DarkDropError::Overflow)?;
    }
    {
        let vault = &mut ctx.accounts.vault;
        vault.total_drops = vault.total_drops
            .checked_add(1)
            .ok_or(DarkDropError::Overflow)?;
    }

    emit!(DropCreatedInPoolSpl {
        mint: ctx.accounts.mint.key(),
        leaf_index,
        pool_leaf,
        pool_merkle_root: pool_root,
        timestamp: Clock::get()?.unix_timestamp,
    });

    msg!(
        "SPL pool drop: mint={} index={}",
        ctx.accounts.mint.key(),
        leaf_index
    );
    Ok(())
}

#[derive(Accounts)]
pub struct CreateDropToPoolSpl<'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [b"mint_config", mint.key().as_ref()],
        bump = mint_config.bump,
        has_one = mint,
        has_one = mint_vault,
    )]
    pub mint_config: Account<'info, MintConfig>,

    #[account(
        mut,
        seeds = [b"note_pool_tree_spl", mint.key().as_ref()],
        bump,
    )]
    pub note_pool_tree_spl: AccountLoader<'info, NotePoolTreeSpl>,

    #[account(
        mut,
        seeds = [b"mint_vault", mint.key().as_ref()],
        bump,
    )]
    pub mint_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = user,
    )]
    pub user_ata: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct DropCreatedInPoolSpl {
    pub mint: Pubkey,
    pub leaf_index: u32,
    pub pool_leaf: [u8; 32],
    pub pool_merkle_root: [u8; 32],
    pub timestamp: i64,
}
