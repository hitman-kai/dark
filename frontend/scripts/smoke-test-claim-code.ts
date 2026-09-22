/**
 * Smoke test for `frontend/src/lib/claim-code.ts` USDC `mint` field.
 *
 * Verifies:
 *   1. SOL round-trip with no mint → decoded mint is undefined
 *   2. USDC round-trip with Circle devnet USDC → decoded mint matches
 *   3. Pre-USDC SOL code (hand-crafted JSON without "m") still decodes
 *   4. USDC encode without mint throws a clear error
 *   5. SOL encode with a stray `payload.mint` silently drops it (the
 *      contract is "SOL codes never carry mint" — encoder enforces)
 *
 * Pure in-memory test — no RPC, no wallet, no chain calls.
 */

import {
  encodeClaimCode,
  decodeClaimCode,
  type ClaimCodePayload,
} from "../src/lib/claim-code";

const DEVNET_USDC_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

let failures = 0;
function check(label: string, ok: boolean, detail?: string) {
  const tag = ok ? "PASS" : "FAIL";
  console.log(`  [${tag}] ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
}

// Base payload — re-used across cases. The numbers are arbitrary but
// deterministic; we're only verifying serialization round-trip behavior.
function basePayload(): ClaimCodePayload {
  return {
    secret: 0x1234567890abcdef1234567890abcdefn,
    nullifier: 0xdeadbeefdeadbeefdeadbeefdeadbeefn,
    amount: 25_000_000n, // arbitrary base units
    blindingFactor: 0xfacefeedfacefeedfacefeedfacefeedn,
    leafIndex: 7,
    vaultAddress: "3umM7SY6uEbasUoS44KKExNui3mReSw911r9bbNXv3bQ",
  };
}

// Tiny base64url helpers — duplicated here so the test stays self-contained.
function uint8ToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return Buffer.from(binary, "binary")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function main() {
  // ── Case 1: SOL round-trip, no mint ──
  console.log("== Case 1: SOL round-trip (no mint) ==");
  {
    const code = await encodeClaimCode(basePayload(), "devnet", "sol");
    check("URI prefix is darkdrop:v4:devnet:sol:raw:", code.startsWith("darkdrop:v4:devnet:sol:raw:"));
    const decoded = await decodeClaimCode(code);
    check("decoded.asset === sol", decoded.asset === "sol");
    check("decoded.payload.mint is undefined", decoded.payload.mint === undefined);
    check(
      "secret/nullifier/amount/blinding round-trip",
      decoded.payload.secret === basePayload().secret &&
        decoded.payload.nullifier === basePayload().nullifier &&
        decoded.payload.amount === basePayload().amount &&
        decoded.payload.blindingFactor === basePayload().blindingFactor &&
        decoded.payload.leafIndex === basePayload().leafIndex &&
        decoded.payload.vaultAddress === basePayload().vaultAddress
    );
  }

  // ── Case 2: USDC round-trip ──
  console.log("== Case 2: USDC round-trip (with Circle devnet USDC) ==");
  {
    const payload = { ...basePayload(), mint: DEVNET_USDC_MINT };
    const code = await encodeClaimCode(payload, "devnet", "usdc");
    check("URI prefix is darkdrop:v4:devnet:usdc:raw:", code.startsWith("darkdrop:v4:devnet:usdc:raw:"));
    const decoded = await decodeClaimCode(code);
    check("decoded.asset === usdc", decoded.asset === "usdc");
    check(
      `decoded.payload.mint === ${DEVNET_USDC_MINT}`,
      decoded.payload.mint === DEVNET_USDC_MINT,
      `got ${decoded.payload.mint}`
    );
  }

  // ── Case 3: hand-crafted pre-USDC SOL code (no "m" key in JSON) ──
  console.log("== Case 3: pre-USDC SOL code (hand-crafted, no \"m\") ==");
  {
    // Build a JSON payload that exactly matches the pre-USDC encoder output —
    // no "m" field, no "p" / "f" either. Then base64url-wrap.
    const json = JSON.stringify({
      s: "5J7E5", // small base58, no special meaning
      n: "5J7E6",
      a: "12345",
      b: "5J7E7",
      i: 3,
      v: "3umM7SY6uEbasUoS44KKExNui3mReSw911r9bbNXv3bQ",
    });
    const encoded = uint8ToBase64url(new TextEncoder().encode(json));
    const code = `darkdrop:v4:devnet:sol:raw:${encoded}`;

    let decoded;
    let threw = false;
    try {
      decoded = await decodeClaimCode(code);
    } catch (e) {
      threw = true;
      console.log("  unexpected throw:", (e as Error).message);
    }
    check("legacy code decodes without throwing", !threw);
    if (decoded) {
      check("decoded.payload.mint === undefined", decoded.payload.mint === undefined);
      check("decoded.payload.amount === 12345n", decoded.payload.amount === 12345n);
      check("decoded.asset === sol", decoded.asset === "sol");
      check("decoded.payload.flavor === standard (default)", decoded.payload.flavor === "standard");
    }
  }

  // ── Case 4: USDC encode without mint → throws ──
  console.log("== Case 4: USDC encode without mint throws ==");
  {
    let threw = false;
    let msg = "";
    try {
      await encodeClaimCode(basePayload(), "devnet", "usdc");
    } catch (e) {
      threw = true;
      msg = (e as Error).message;
    }
    check("throws when asset=usdc and mint missing", threw, `error: ${msg}`);
    check(
      "error message mentions 'mint' and 'usdc'",
      threw && msg.toLowerCase().includes("mint") && msg.toLowerCase().includes("usdc"),
      `got: ${msg}`
    );
  }

  // ── Case 5: SOL encode with stray mint → silently dropped ──
  console.log("== Case 5: SOL encode with stray payload.mint (should drop silently) ==");
  {
    const payload = { ...basePayload(), mint: DEVNET_USDC_MINT };
    const code = await encodeClaimCode(payload, "devnet", "sol");
    check("encode succeeds (no throw)", typeof code === "string" && code.length > 0);
    // The encoded payload must NOT contain "m" anywhere — easiest check is
    // to decode and confirm mint is undefined.
    const decoded = await decodeClaimCode(code);
    check("decoded.payload.mint is undefined", decoded.payload.mint === undefined);
    // Also sanity-check the URI hasn't picked up "usdc" anywhere.
    check("URI still uses :sol: in prefix", code.startsWith("darkdrop:v4:devnet:sol:raw:"));
  }

  console.log("");
  if (failures > 0) {
    console.error(`[smoke] FAILED — ${failures} check(s)`);
    process.exit(1);
  }
  console.log(`[smoke] PASS — all checks green`);
}

main().catch((e) => {
  console.error("[smoke] crashed:", e?.stack || e);
  process.exit(1);
});
