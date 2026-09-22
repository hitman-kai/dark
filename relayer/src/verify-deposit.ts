/**
 * DarkDrop V4 — strict deposit-transaction verification (issue #19 / F3).
 *
 * A relayed deposit must be a transaction that the depositor PURPOSE-BUILT for
 * this exact deposit — not merely any tx that happened to credit the relayer.
 * We verify, against the parsed on-chain tx, that it contains:
 *
 *   1. EXACTLY one SPL Memo instruction (pinned program id) whose content == `nonce`
 *   2. EXACTLY one System `transfer` instruction with accounts exactly
 *      [source = declared `payer`, destination = relayer] for `lamports == amount`
 *   3. ZERO OR MORE ComputeBudget instructions (priority-fee / CU-limit), which
 *      real wallets (e.g. Phantom) inject. They move no funds and touch no
 *      accounts — the fee is paid by the tx fee-payer (the depositor) — so they
 *      are benign and tolerated. (This previously required EXACTLY 2 instructions,
 *      which intermittently rejected legit deposits when a wallet injected a
 *      ComputeBudget ix — see issue #38.)
 *
 * Any OTHER program, a second transfer/memo, address-table lookups, a failed tx,
 * a wrong source/destination, a >= (vs ==) amount, or a missing/mismatched memo
 * all cause rejection. The single-use `nonce` (committed in the memo) binds the
 * funded transfer to one specific deposit and powers the no-TTL replay guard
 * (see processed-txs.ts).
 */

import { Connection } from "@solana/web3.js";

const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";
// Pinned SPL Memo program (v2). The memo MUST come from exactly this program.
const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
// ComputeBudget program. Its instructions (SetComputeUnitLimit / SetComputeUnitPrice
// / etc.) set the tx's compute limit and priority fee — paid by the tx fee-payer
// (the depositor), moving no funds and touching no accounts. Real wallets inject
// these, so they are tolerated alongside the transfer + memo (issue #38).
const COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111";

export interface DepositBinding {
  payer: string; // declared source pubkey (base58)
  relayer: string; // relayer pubkey (base58)
  amount: bigint; // exact lamports the transfer must carry
  nonce: string; // per-deposit single-use nonce, committed in the tx memo
}

export type VerifyResult = { ok: true } | { ok: false; error: string };

/** A nonce is a 32-byte value rendered as 64 lowercase hex chars. */
export function isValidNonce(nonce: unknown): nonce is string {
  return typeof nonce === "string" && /^[0-9a-f]{64}$/.test(nonce);
}

export async function verifyDepositTx(
  connection: Connection,
  signature: string,
  b: DepositBinding
): Promise<VerifyResult> {
  if (!isValidNonce(b.nonce)) {
    return { ok: false, error: "nonce must be 64 lowercase hex chars (32 bytes)" };
  }

  const tx = await connection.getParsedTransaction(signature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });
  if (!tx) return { ok: false, error: "Deposit TX not found or not confirmed" };
  if (tx.meta?.err) return { ok: false, error: "Deposit TX failed on-chain" };

  // Reject address-lookup-table usage: a plain deposit never needs it, and it
  // is a vector for hiding accounts from a naive parser.
  const loaded = tx.meta?.loadedAddresses;
  if ((loaded?.writable?.length ?? 0) > 0 || (loaded?.readonly?.length ?? 0) > 0) {
    return { ok: false, error: "Deposit TX must not use address lookup tables" };
  }

  const ixs = tx.transaction.message.instructions as any[];
  // STRICT shape: exactly one transfer + exactly one memo, plus any number of
  // benign ComputeBudget ixs (wallet priority-fee injection). Every other
  // program — and a second transfer or a second memo — is rejected below.

  let sawTransfer = false;
  let sawMemo = false;

  for (const ix of ixs) {
    const programId: string = ix.programId?.toString?.() ?? "";

    if (programId === SYSTEM_PROGRAM_ID) {
      if (sawTransfer) return { ok: false, error: "More than one System instruction" };
      const parsed = ix.parsed;
      if (!parsed || parsed.type !== "transfer") {
        return { ok: false, error: "System instruction is not a plain transfer" };
      }
      const info = parsed.info ?? {};
      if (info.source !== b.payer) {
        return { ok: false, error: "Transfer source is not the declared payer" };
      }
      if (info.destination !== b.relayer) {
        return { ok: false, error: "Transfer destination is not the relayer" };
      }
      let lamports: bigint;
      try {
        lamports = BigInt(info.lamports);
      } catch {
        return { ok: false, error: "Transfer lamports not an integer" };
      }
      if (lamports !== b.amount) {
        return { ok: false, error: `Transfer is ${lamports} lamports, expected exactly ${b.amount}` };
      }
      sawTransfer = true;
    } else if (programId === MEMO_PROGRAM_ID) {
      if (sawMemo) return { ok: false, error: "More than one memo instruction" };
      // jsonParsed renders a spl-memo instruction's content as a string in `parsed`.
      const memo = typeof ix.parsed === "string" ? ix.parsed : null;
      if (memo === null) {
        return { ok: false, error: "Memo instruction could not be parsed" };
      }
      if (memo !== b.nonce) {
        return { ok: false, error: "Memo does not equal the declared nonce" };
      }
      sawMemo = true;
    } else if (programId === COMPUTE_BUDGET_PROGRAM_ID) {
      // Benign: sets CU limit / priority fee (paid by the depositor fee-payer),
      // moves no funds, touches no accounts. Tolerated in any number (issue #38).
      continue;
    } else {
      return { ok: false, error: `Unexpected instruction program ${programId} in deposit TX` };
    }
  }

  if (!sawTransfer) return { ok: false, error: "No System transfer to the relayer in deposit TX" };
  if (!sawMemo) return { ok: false, error: "No memo (nonce) in deposit TX" };
  return { ok: true };
}
