use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod merkle_tree;
pub mod poseidon;
pub mod state;
pub mod verifier;
pub mod vk;

use instructions::*;
use state::ProofData;

declare_id!("GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU");

#[program]
pub mod darkdrop {
    use super::*;

    /// Initialize the DarkDrop vault, Merkle tree, and treasury.
    pub fn initialize_vault(ctx: Context<InitializeVault>, drop_cap: u64) -> Result<()> {
        instructions::initialize::handle_initialize_vault(ctx, drop_cap)
    }

    /// Create a new drop: accept SOL, insert leaf into Merkle tree.
    pub fn create_drop<'info>(
        ctx: Context<'_, '_, '_, 'info, CreateDrop<'info>>,
        leaf: [u8; 32],
        amount: u64,
    ) -> Result<()> {
        instructions::create_drop::handle_create_drop(ctx, leaf, amount)
    }

    // Legacy V1 `claim` (direct-SOL, 6 public inputs) was retired in #18: its
    // ZK circuit source was absent from the repo, so the V1 nullifier
    // derivation could not be audited against V2's in the shared
    // [b"nullifier", hash] namespace (cross-version double-spend surface). V2
    // `claim_credit` supersedes it. See verifier.rs / vk.rs (verify_proof and
    // verifying_key_v1 removed).

    /// Claim as credit note: verify ZK proof (V2 circuit, 5 public inputs),
    /// store re-randomized commitment in CreditNote PDA. ZERO SOL moves.
    /// Salt randomizes the stored commitment to prevent deposit→claim linkage.
    pub fn claim_credit(
        ctx: Context<ClaimCredit>,
        nullifier_hash: [u8; 32],
        proof: ProofData,
        inputs: Vec<u8>,
        salt: [u8; 32],
    ) -> Result<()> {
        instructions::claim_credit::handle_claim_credit(ctx, nullifier_hash, proof, inputs, salt)
    }

    /// One-time migration: create Treasury PDA on existing deployments.
    pub fn create_treasury(ctx: Context<CreateTreasury>) -> Result<()> {
        instructions::create_treasury::handle_create_treasury(ctx)
    }

    /// Withdraw from credit note: open commitment, transfer SOL via direct
    /// lamport manipulation (no CPI, no inner instruction).
    pub fn withdraw_credit(
        ctx: Context<WithdrawCredit>,
        nullifier_hash: [u8; 32],
        opening: Vec<u8>,
        rate: u16,
    ) -> Result<()> {
        instructions::withdraw_credit::handle_withdraw_credit(ctx, nullifier_hash, opening, rate)
    }

    /// Admin sweep: transfer excess SOL from treasury to authority wallet.
    /// Limited to treasury_balance - outstanding_obligations - rent_exempt_min.
    /// Only callable by vault authority.
    pub fn admin_sweep(ctx: Context<AdminSweep>) -> Result<()> {
        instructions::admin_sweep::handle_admin_sweep(ctx)
    }

    /// One-time migration: reallocate vault to include total_deposited/total_withdrawn.
    pub fn migrate_vault(ctx: Context<MigrateVault>) -> Result<()> {
        instructions::migrate_vault::handle_migrate_vault(ctx)
    }

    /// Initialize the Note Pool — second-layer Merkle tree for credit note mixing.
    /// Only callable by vault authority.
    pub fn initialize_note_pool(ctx: Context<InitializeNotePool>) -> Result<()> {
        instructions::initialize_note_pool::handle_initialize_note_pool(ctx)
    }

    /// Deposit a credit note into the note pool for second-layer mixing.
    /// Opens the credit note commitment, constructs a pool leaf with VERIFIED amount.
    /// Zero SOL moves. The credit note PDA is closed.
    pub fn deposit_to_note_pool(
        ctx: Context<DepositToNotePool>,
        nullifier_hash: [u8; 32],
        opening: Vec<u8>,
        pool_params: Vec<u8>,
    ) -> Result<()> {
        instructions::deposit_to_note_pool::handle_deposit_to_note_pool(
            ctx, nullifier_hash, opening, pool_params,
        )
    }

    /// Claim a fresh credit note from the note pool.
    /// Verifies Groth16 proof (V3 circuit), creates a fresh CreditNote PDA.
    /// Zero SOL moves. No amounts visible. Second layer of recursive privacy.
    pub fn claim_from_note_pool(
        ctx: Context<ClaimFromNotePool>,
        pool_nullifier_hash: [u8; 32],
        proof: ProofData,
        inputs: Vec<u8>,
    ) -> Result<()> {
        instructions::claim_from_note_pool::handle_claim_from_note_pool(
            ctx, pool_nullifier_hash, proof, inputs,
        )
    }

    /// Revoke an unclaimed drop after the time-lock expires.
    /// Depositor submits the leaf preimage; program reconstructs the leaf
    /// on-chain to bind the nullifier. Refund via direct lamport manipulation.
    pub fn revoke_drop(
        ctx: Context<RevokeDrop>,
        leaf: [u8; 32],
        nullifier_hash: [u8; 32],
        preimage: Vec<u8>,
    ) -> Result<()> {
        instructions::revoke_drop::handle_revoke_drop(ctx, leaf, nullifier_hash, preimage)
    }

    /// Close an unused DepositReceipt and return rent to the depositor.
    /// Unconditional: depositor signs, no nullifier state check (see Audit 04 M-01).
    /// Closing surrenders the revoke option for that drop.
    pub fn close_receipt(
        ctx: Context<CloseReceipt>,
        leaf: [u8; 32],
    ) -> Result<()> {
        instructions::close_receipt::handle_close_receipt(ctx, leaf)
    }

    /// One-time schema v2 migration: reallocate MerkleTreeAccount and
    /// NotePoolTree to ROOT_HISTORY_SIZE=256. Idempotent per-tree.
    pub fn migrate_schema_v2(ctx: Context<MigrateSchemaV2>) -> Result<()> {
        instructions::migrate_schema_v2::handle_migrate_schema_v2(ctx)
    }

    /// Propose a new vault authority. Signed by current authority; opens
    /// a single-at-a-time sidecar PDA. Does not change vault.authority.
    pub fn propose_authority_rotation(
        ctx: Context<ProposeAuthorityRotation>,
        new_authority: Pubkey,
    ) -> Result<()> {
        instructions::authority_rotation::handle_propose_authority_rotation(ctx, new_authority)
    }

    /// Current authority withdraws its own proposal. Closes the sidecar.
    pub fn revoke_authority_rotation(ctx: Context<RevokeAuthorityRotation>) -> Result<()> {
        instructions::authority_rotation::handle_revoke_authority_rotation(ctx)
    }

    /// New authority accepts the proposal. Flips vault.authority and
    /// closes the sidecar. Signer must match the proposed pubkey.
    pub fn accept_authority_rotation(ctx: Context<AcceptAuthorityRotation>) -> Result<()> {
        instructions::authority_rotation::handle_accept_authority_rotation(ctx)
    }

    /// Deposit SOL directly into the Note Pool layer. One-TX equivalent of
    /// create_drop + claim_credit + deposit_to_note_pool. Eliminates the
    /// temporal correlation an observer could draw from the three-step
    /// sequence. No dishonest-leaf risk: amount is the literal CPI transfer.
    pub fn create_drop_to_pool(
        ctx: Context<CreateDropToPool>,
        amount: u64,
        pool_params: Vec<u8>,
    ) -> Result<()> {
        instructions::create_drop_to_pool::handle_create_drop_to_pool(ctx, amount, pool_params)
    }

    /// Register a new SPL mint with the program. Smallest viable surface:
    /// creates the `MintConfig` PDA only; trees and mint vault are set up
    /// by a later instruction. Authority-gated via Vault.has_one.
    pub fn initialize_mint_config(ctx: Context<InitializeMintConfig>) -> Result<()> {
        instructions::initialize_mint_config::handle_initialize_mint_config(ctx)
    }

    /// Initialize the per-mint main Merkle tree and note pool tree.
    /// Mint must already be registered via `initialize_mint_config`.
    /// Authority-gated via Vault.has_one.
    pub fn initialize_mint_trees(ctx: Context<InitializeMintTrees>) -> Result<()> {
        instructions::initialize_mint_trees::handle_initialize_mint_trees(ctx)
    }

    /// Create the program-owned SPL token account that holds custody for
    /// this mint. Trees must already be initialized. Authority-gated.
    pub fn initialize_mint_vault(ctx: Context<InitializeMintVault>) -> Result<()> {
        instructions::initialize_mint_vault::handle_initialize_mint_vault(ctx)
    }

    /// SPL parallel of `create_drop`. Accepts an SPL token deposit into
    /// the program-owned mint vault and inserts the leaf into the per-mint
    /// Merkle tree. User-facing.
    pub fn create_drop_spl(
        ctx: Context<CreateDropSpl>,
        leaf: [u8; 32],
        amount: u64,
    ) -> Result<()> {
        instructions::create_drop_spl::handle_create_drop_spl(ctx, leaf, amount)
    }

    /// SPL parallel of `claim_credit`. Verifies a V2 ZK proof, creates a
    /// per-mint nullifier and a CreditNoteSpl with re-randomized
    /// commitment. ZERO TOKEN MOVEMENT.
    pub fn claim_credit_spl(
        ctx: Context<ClaimCreditSpl>,
        nullifier_hash: [u8; 32],
        proof: ProofData,
        inputs: Vec<u8>,
        salt: [u8; 32],
    ) -> Result<()> {
        instructions::claim_credit_spl::handle_claim_credit_spl(
            ctx, nullifier_hash, proof, inputs, salt,
        )
    }

    /// SPL parallel of `withdraw_credit`. Opens the CreditNoteSpl
    /// commitment, transfers tokens out of the mint vault, closes the
    /// note. Supports the same `rate` basis-points fee model as the
    /// SOL flow (≤ 500 bps), with the fee paid in source mint to payer.
    pub fn withdraw_credit_spl(
        ctx: Context<WithdrawCreditSpl>,
        nullifier_hash: [u8; 32],
        opening: Vec<u8>,
        rate: u16,
    ) -> Result<()> {
        instructions::withdraw_credit_spl::handle_withdraw_credit_spl(
            ctx, nullifier_hash, opening, rate,
        )
    }

    /// Admin kill-switch for a registered mint. Flips
    /// `MintConfig.paused`; subsequent `create_drop_spl` calls return
    /// `MintPaused` while existing credit notes remain withdrawable.
    pub fn pause_deposits(
        ctx: Context<PauseDeposits>,
        paused: bool,
    ) -> Result<()> {
        instructions::pause_deposits::handle_pause_deposits(ctx, paused)
    }

    /// SPL parallel of `admin_sweep`. Sweeps excess tokens out of the
    /// mint vault to an admin-chosen destination ATA, never below the
    /// user-owed floor (total_deposited - total_withdrawn).
    pub fn admin_sweep_spl(
        ctx: Context<AdminSweepSpl>,
        amount: u64,
    ) -> Result<()> {
        instructions::admin_sweep_spl::handle_admin_sweep_spl(ctx, amount)
    }

    /// SPL parallel of `create_drop_to_pool`. One-TX deposit of SPL
    /// tokens directly into the per-mint note pool layer. Skips the
    /// main tree; the V3 claim path picks it up.
    pub fn create_drop_to_pool_spl(
        ctx: Context<CreateDropToPoolSpl>,
        amount: u64,
        pool_params: Vec<u8>,
    ) -> Result<()> {
        instructions::create_drop_to_pool_spl::handle_create_drop_to_pool_spl(
            ctx, amount, pool_params,
        )
    }

    /// SPL parallel of `claim_from_note_pool`. Verifies a V3 proof
    /// against the per-mint pool tree, creates a per-mint pool
    /// nullifier and a fresh CreditNoteSpl. ZERO TOKEN MOVEMENT.
    pub fn claim_from_note_pool_spl(
        ctx: Context<ClaimFromNotePoolSpl>,
        pool_nullifier_hash: [u8; 32],
        proof: ProofData,
        inputs: Vec<u8>,
    ) -> Result<()> {
        instructions::claim_from_note_pool_spl::handle_claim_from_note_pool_spl(
            ctx, pool_nullifier_hash, proof, inputs,
        )
    }
}
