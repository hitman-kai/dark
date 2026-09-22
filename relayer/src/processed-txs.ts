/**
 * Persistent single-use deposit-nonce tracker — survives relayer restarts.
 *
 * Issue #19 (F3): replay is keyed on the per-deposit NONCE (committed in the
 * deposit tx's memo), not the bare tx signature, and entries NEVER expire.
 * A nonce is single-use for all time, so a deposit can never be replayed —
 * including across what used to be the 24h TTL window. (Removing the TTL is
 * the fix; a settlement/dispute window can be arbitrarily long.)
 *
 * The stored value records the on-chain signature + first-seen timestamp for
 * audit only; the KEY is the nonce.
 */

import fs from "fs";
import path from "path";

const STORE_PATH = path.join(__dirname, "..", "data", "processed-deposits.json");

interface Entry {
  ts: number; // unix ms, first seen (audit only)
  sig?: string; // deposit tx signature (audit only)
}

let cache: Record<string, Entry> = {};

function ensureDir() {
  const dir = path.dirname(STORE_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function load() {
  try {
    if (fs.existsSync(STORE_PATH)) {
      cache = JSON.parse(fs.readFileSync(STORE_PATH, "utf8"));
    }
  } catch {
    cache = {};
  }
  // No pruning: nonces are single-use forever (issue #19 / F3).
}

function save() {
  ensureDir();
  fs.writeFileSync(STORE_PATH, JSON.stringify(cache), "utf8");
}

// Load on startup
load();

/** Has this deposit nonce been used before? */
export function hasProcessedNonce(nonce: string): boolean {
  return nonce in cache;
}

/** Mark a deposit nonce as used (optionally recording the tx signature). */
export function markProcessed(nonce: string, sig?: string) {
  cache[nonce] = { ts: Date.now(), sig };
  save();
}

/** Roll back a nonce if the on-chain relay TX failed, so the user can retry. */
export function unmarkProcessed(nonce: string) {
  delete cache[nonce];
  save();
}
