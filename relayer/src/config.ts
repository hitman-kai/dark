/**
 * DarkDrop V4 — Relayer Configuration
 */

const feeRateBps = parseInt(process.env.FEE_RATE_BPS || "50");
if (feeRateBps < 0 || feeRateBps > 500) {
  throw new Error(`FEE_RATE_BPS=${feeRateBps} out of bounds (0-500). Refusing to start.`);
}

// Solana caps compute units at 1,400,000 per TX. Anything outside [1, 1_400_000]
// is either nonsense (NaN from a malformed env) or unsatisfiable. Fail fast at
// startup rather than letting `setComputeUnitLimit({ units: NaN })` reach a TX.
function parseCu(name: string, raw: string | undefined, fallback: string): number {
  const parsed = parseInt(raw || fallback, 10);
  if (!Number.isFinite(parsed) || parsed < 1 || parsed > 1_400_000) {
    throw new Error(`${name}=${raw} is invalid (expected integer 1..1400000). Refusing to start.`);
  }
  return parsed;
}

export const config = {
  // Solana RPC
  rpcUrl: process.env.RPC_URL || "https://api.devnet.solana.com",

  // Relayer keypair path (fee payer)
  keypairPath:
    process.env.RELAYER_KEYPAIR || "~/.config/solana/relayer.json",

  // SOL program ID. Defaults to the live program. For testing the new binary's
  // SOL behavior against the test program, set SOL_PROGRAM_ID=8b8JX1nh...
  // before starting the relayer. DO NOT commit a non-default override.
  programId:
    process.env.SOL_PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU",

  // SPL routes target the test program until the live program is upgraded
  // with USDC support. SOL routes continue to use `programId` above.
  splProgramId:
    process.env.TEST_PROGRAM_ID || "8b8JX1nhcG5UryRUE6Zm85LLcTA6PjquEkUVwWRV6Rrn",

  // Relay fee: percentage of claim amount (basis points, 100 = 1%, max 500 = 5%)
  feeRateBps,

  // Allowed frontend origin for CORS (CORS_ORIGIN must be set in production)
  corsOrigin: process.env.CORS_ORIGIN || "http://localhost:3000",

  // Server port
  port: parseInt(process.env.PORT || "3001"),

  // Rate limiting
  rateLimit: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 10, // per IP per window
  },

  // Max claim amount the relayer will process (in lamports)
  maxClaimAmount: BigInt(process.env.MAX_CLAIM || "100000000000"), // 100 SOL

  // Compute-unit budgets per relay endpoint. Each route runs a Groth16
  // verification on-chain. V1 verifies a 6-public-input proof and costs less
  // than V2/V3. Defaults match the previously hardcoded inline values.
  // Bump these via env if a runtime repricing or verifier upgrade pushes
  // cost over budget.
  v1ClaimCu: parseCu("V1_CLAIM_CU", process.env.V1_CLAIM_CU, "200000"),
  v2CreditClaimCu: parseCu("V2_CREDIT_CLAIM_CU", process.env.V2_CREDIT_CLAIM_CU, "400000"),
  v2CreditSplClaimCu: parseCu("V2_CREDIT_SPL_CLAIM_CU", process.env.V2_CREDIT_SPL_CLAIM_CU, "400000"),
  v3PoolClaimCu: parseCu("V3_POOL_CLAIM_CU", process.env.V3_POOL_CLAIM_CU, "400000"),
};

// ── CORS allow-list ───────────────────────────────────────────────────────────
// A fund-fronting relayer keeps a TIGHT allow-list — no `*`, no `origin: true`,
// no blanket `*.vercel.app`. Exactly two things are allowed:
//   1. config.corsOrigin — the env-configured frontend origin (CORS_ORIGIN;
//      https://darkdrop.app in prod, http://localhost:3000 dev default).
//   2. THIS project's Vercel BRANCH-preview URLs only: project "darkdropv4",
//      team slug "generalhitobusiness-3091s-projects".
// Anchored ^…$, https-only, no ports/paths/extra subdomains; the branch-slug
// segment is [a-z0-9-]+ (Vercel lowercases/sanitizes branch names). Example:
//   https://darkdropv4-git-fix-issue-38-deposit-client-generalhitobusiness-3091s-projects.vercel.app
export const CORS_PREVIEW_PATTERN =
  /^https:\/\/darkdropv4-git-[a-z0-9-]+-generalhitobusiness-3091s-projects\.vercel\.app$/;

/**
 * CORS origin decision used by the `cors` middleware in index.ts.
 * A missing Origin (undefined) is a non-browser / same-origin request — CORS
 * does not gate those (not a cross-site browser threat), so allow. Otherwise
 * allow only the configured origin or a scoped preview URL; reject everything else.
 */
export function isAllowedCorsOrigin(origin: string | undefined): boolean {
  if (!origin) return true;
  if (origin === config.corsOrigin) return true;
  return CORS_PREVIEW_PATTERN.test(origin);
}
