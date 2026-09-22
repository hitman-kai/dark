use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use crate::state::*;
use crate::errors::DarkDropError;
use crate::poseidon::poseidon_hash;

/// SPL parallel of `create_drop` for SOL. Accepts an SPL token deposit
/// into the program-owned mint vault and inserts the depositor's leaf
/// into the per-mint Merkle tree.
///
/// Structurally mirrors `create_drop.rs` to keep audit coverage on the
/// SOL ix transferable: same validation order, same overflow-guarded
/// counter updates, same leaf-append algorithm.
///
/// Differences from SOL flow:
///   1. Token movement via `token::transfer` CPI instead of
///      `system_program::transfer`.
///   2. New `require!(!mint_config.paused, MintPaused)` gate.
///   3. Per-mint deposit counter on `MintConfig.total_deposited` (in
///      mint base units) — global `Vault.total_deposited` stays
///      lamport-only.
///   4. DepositReceipt / revoke path deferred — see comments below.
pub fn handle_create_drop_spl(
    ctx: Context<CreateDropSpl>,
    leaf: [u8; 32],
    amount: u64,
) -> Result<()> {
    // 1. Amount validation — mirrors create_drop.rs:27-31.
    //
    // NOTE: `MIN_DEPOSIT_LAMPORTS` and `Vault.drop_cap` are lamport-
    // denominated for SOL. For SPL we reuse them as raw-base-unit
    // thresholds, which is intentionally loose for the first SPL ix —
    // the same numeric bound applies regardless of mint decimals.
    // A real per-mint cap will ship later as a `MintConfig` field
    // once we have enough mints to justify the schema bump.
    require!(amount >= MIN_DEPOSIT_LAMPORTS, DarkDropError::BelowMinDeposit);
    require!(
        amount <= ctx.accounts.vault.drop_cap,
        DarkDropError::AmountExceedsCap
    );

    // 2. Mint paused check — new for SPL. Kill-switch closes new deposits
    // for this mint without affecting outstanding withdrawals, so users
    // always have a path to exit.
    require!(
        !ctx.accounts.mint_config.paused,
        DarkDropError::MintPaused
    );

    // 3. SPL transfer user_ata → mint_vault. Equivalent of the SOL
    // `system_program::transfer` from create_drop.rs:36-45. The user
    // signs as the source ATA's authority (token::authority constraint
    // on user_ata enforces that user.key() owns user_ata).
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

    // 4. Merkle leaf insertion — algorithm IDENTICAL to
    // `merkle_tree_append` in merkle_tree.rs. Inlined here so this SPL
    // extension does not modify the audited merkle_tree.rs file. If a
    // third SPL caller needs the same loop, factor into a
    // `merkle_tree_spl_append` helper at that point.
    let current_root;
    let leaf_index;
    {
        let tree = &mut ctx.accounts.merkle_tree_spl.load_mut()?;
        let max_capacity = 1u32 << MERKLE_DEPTH;
        require!(tree.next_index < max_capacity, DarkDropError::TreeFull);

        leaf_index = tree.next_index;
        let mut current_index = tree.next_index as usize;
        let mut current_level_hash = leaf;
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
        // Local for the new root index — extracted to dodge a two-phase
        // borrow failure when the access goes through `RefMut`. The
        // equivalent line in `merkle_tree_append` compiles directly
        // because it operates on a `&mut MerkleTreeAccount`.
        let new_root_idx =
            (tree.root_history_index + 1) % ROOT_HISTORY_SIZE as u32;
        tree.root_history_index = new_root_idx;
        tree.root_history[new_root_idx as usize] = current_level_hash;
        tree.next_index = tree.next_index
            .checked_add(1)
            .ok_or(DarkDropError::Overflow)?;
        current_root = tree.current_root;
    }

    // 5. Counter updates. Per-mint volume lives on MintConfig (in mint
    // base units); global drop count lives on Vault (cross-asset).
    // Mirrors create_drop.rs:58-66 for the global counter; the per-mint
    // counter is the SPL-only analog.
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

    // 6. DepositReceipt / revoke path: intentionally NOT implemented in
    // this first SPL ix. The SOL receipt at [b"receipt", leaf] holds no
    // mint field, so a SPL receipt at the same seeds would collide with
    // SOL receipts and a future revoke_drop_spl could not disambiguate.
    // The fix is a new namespace (e.g. [b"receipt_spl", mint, leaf]) or
    // a CreditReceiptSpl struct with a mint field; either way it must
    // compose with revoke_drop_spl. Defer both together.

    emit!(DropCreatedSpl {
        mint: ctx.accounts.mint.key(),
        leaf_index,
        leaf,
        merkle_root: current_root,
        timestamp: Clock::get()?.unix_timestamp,
    });

    msg!(
        "SPL drop created: mint={} index={}",
        ctx.accounts.mint.key(),
        leaf_index
    );

    Ok(())
}

#[derive(Accounts)]
pub struct CreateDropSpl<'info> {
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
        seeds = [b"merkle_tree_spl", mint.key().as_ref()],
        bump,
    )]
    pub merkle_tree_spl: AccountLoader<'info, MerkleTreeSpl>,

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
pub struct DropCreatedSpl {
    pub mint: Pubkey,
    pub leaf_index: u32,
    pub leaf: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: i64,
}
