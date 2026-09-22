use anchor_lang::prelude::*;

#[error_code]
pub enum DarkDropError {
    #[msg("Merkle tree is full")]
    TreeFull,

    #[msg("Invalid Merkle root — not found in root history")]
    InvalidRoot,

    #[msg("Nullifier has already been spent")]
    NullifierAlreadySpent,

    #[msg("Invalid ZK proof")]
    InvalidProof,

    #[msg("Amount exceeds drop cap")]
    AmountExceedsCap,

    #[msg("Amount must be greater than zero")]
    ZeroAmount,

    #[msg("Arithmetic overflow")]
    Overflow,

    #[msg("Insufficient vault balance")]
    InsufficientBalance,

    #[msg("Fee exceeds claim amount")]
    FeeTooHigh,

    #[msg("Commitment verification failed")]
    CommitmentMismatch,

    #[msg("Unauthorized withdrawal")]
    UnauthorizedWithdraw,

    #[msg("Invalid input data length")]
    InvalidInputLength,

    #[msg("Amount below minimum deposit")]
    BelowMinDeposit,

    #[msg("Vault already migrated")]
    AlreadyMigrated,

    #[msg("Revoke attempted before timeout expired")]
    RevokeTooEarly,

    #[msg("Unauthorized revoke: signer is not the depositor")]
    UnauthorizedRevoke,

    #[msg("Drop already claimed or revoked")]
    DropAlreadyClaimed,

    #[msg("Invalid DepositReceipt account in create_drop remaining_accounts")]
    InvalidDepositReceipt,

    #[msg("A deposit receipt already exists for this leaf")]
    LeafAlreadyDeposited,

    #[msg("Account size does not match any known schema version")]
    InvalidAccountSize,

    #[msg("Signer does not match the proposed new authority")]
    PendingAuthorityMismatch,

    #[msg("Authority rotation acceptance attempted before ROTATION_DELAY elapsed")]
    RotationTooEarly,

    // ─── SPL / multi-mint extension ──────────────────────────────────────────
    /// Audit 06 M-04: the SPL extension is bound to LEGACY SPL Token only.
    /// A Token-2022 mint does NOT surface this error — it fails earlier, at
    /// Anchor account validation (`AccountOwnedByWrongProgram`/`ConstraintTokenMint`),
    /// because `Account<'info, Mint>` rejects the Token-2022 owner/schema before
    /// the handler runs. Token-2022 is intentionally unsupported; see
    /// ARCHITECTURE.md §15 ("Token program binding / Token-2022 scope").
    #[msg("Mint is not registered with the program (note: Token-2022 mints are not supported — see ARCHITECTURE.md §15)")]
    MintNotRegistered,

    #[msg("Mint is paused — new deposits disabled")]
    MintPaused,

    #[msg("Mint does not match the expected mint for this account")]
    WrongMint,

    /// Audit F1 (#17): a Groth16 public input was not a canonical BN254 scalar
    /// (value >= field order r). Non-canonical inputs are scalar-malleable —
    /// `n` and `n + r` verify against the same proof but produce distinct PDA
    /// seeds, enabling nullifier double-spend. Every public input must be < r.
    #[msg("Public input is not a canonical BN254 scalar (value >= field order)")]
    NonCanonicalInput,
}
