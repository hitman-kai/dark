"use client";

import { useState, useEffect } from "react";
import { useWallet, useConnection } from "@solana/wallet-adapter-react";
import {
  Transaction,
  TransactionInstruction,
  SystemProgram,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  getAccount,
  TokenAccountNotFoundError,
  TokenInvalidAccountOwnerError,
} from "@solana/spl-token";
import CodeDisplay from "@/components/CodeDisplay";

import { initPoseidon } from "@/lib/crypto";
import {
  prepareCreateDrop,
  getVaultPDA,
  getMerkleTreePDA,
  getTreasuryPDA,
  PROGRAM_ID,
} from "@/lib/vault";
import {
  DEVNET_USDC_MINT,
  USDC_DECIMALS,
  USDC_MIN_DEPOSIT,
  USDC_MAX_DEPOSIT,
  getMerkleTreeSplPDA,
  getVaultPDA as getSplVaultPDA,
  buildCreateDropSplIx,
} from "@/lib/vault-spl";
import { encodeClaimCode } from "@/lib/claim-code";
import { snapshotTreeAccount } from "@/lib/merkle";
import { RELAYER_URL, checkRelayerHealth } from "@/lib/relayer";
import { sendWithRetry } from "@/lib/send-with-retry";
import {
  getReceiptPDA,
  saveReceipt,
  bytesToHex,
  bigintToHex32,
} from "@/lib/receipt";
import {
  getNotePoolPDA,
  getNotePoolTreePDA,
} from "@/lib/note-pool";
import { randomFieldElement, bigintToBytes32BE } from "@/lib/crypto";

type Stage = "input" | "confirming" | "done" | "error";
type DepositMode = "direct" | "private" | "pool";

// #19 (F3) gate for the relayer-fronted SOL deposit modes ("private"/"pool").
// The relayer deposit endpoints (/api/relay/create-drop, /create-drop-to-pool)
// REQUIRE a per-deposit payer + nonce (SPL Memo on the transfer, exactly 2 ix).
// The frontend client that sends these is implemented (issue #38). false = SOL
// forced to "direct" and the relayer-fronted modes hidden; true = enabled.
// USDC and SOL-direct never route through this gate.
//
// ⚠️ ENABLED on the fix/issue-38-deposit-client branch for PR #40 PREVIEW TESTING
// ONLY. Do NOT merge to main / production with this true until a real-wallet
// deposit confirms the tx is exactly 2 instructions (no ComputeBudget / priority-fee
// injection that would trip the relayer's strict 2-instruction rule).
const SOL_RELAYER_DEPOSITS_ENABLED: boolean = true;
type Asset = "sol" | "usdc";

// sha256("global:create_drop")[0..8]
const CREATE_DROP_DISCRIMINATOR = new Uint8Array([157, 142, 145, 247, 92, 73, 59, 48]);

const MIN_SOL = 0.00001; // 10,000 lamports

/**
 * Parse a decimal USDC amount string into 6-decimal base units (BigInt).
 *
 * FP arithmetic is unsafe here: `parseFloat("0.1") * 1e6` rounds to
 * 100000.00000000001, and `Math.round(parseFloat("123456.789012") * 1e6)`
 * loses precision past ~15 significant digits. A string-based split is
 * exact for any input with ≤ 6 fractional digits, which is the only
 * input class the UI accepts.
 *
 * Returns base units as BigInt. Throws on invalid input or > 6 decimals.
 * Accepts `.` or `,` as separator (some locales auto-comma); coerces to `.`.
 */
function parseUsdcAmount(input: string): bigint {
  const normalized = input.trim().replace(",", ".");
  if (!/^\d*\.?\d*$/.test(normalized) || normalized === "" || normalized === ".") {
    throw new Error("Invalid USDC amount");
  }
  const [whole, frac = ""] = normalized.split(".");
  if (frac.length > USDC_DECIMALS) {
    throw new Error(`USDC supports at most ${USDC_DECIMALS} decimals`);
  }
  const padded = (frac + "0".repeat(USDC_DECIMALS)).slice(0, USDC_DECIMALS);
  // Drop leading zeros from whole to keep BigInt happy on "00.5" style input.
  const wholePart = whole === "" ? "0" : whole;
  return BigInt(wholePart) * 10n ** BigInt(USDC_DECIMALS) + BigInt(padded);
}

/** Format a USDC base-unit amount as a human string. Trims trailing zeros. */
function formatUsdc(baseUnits: bigint): string {
  const denom = 10n ** BigInt(USDC_DECIMALS);
  const whole = baseUnits / denom;
  const frac = baseUnits % denom;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(USDC_DECIMALS, "0").replace(/0+$/, "");
  return fracStr ? `${whole.toString()}.${fracStr}` : whole.toString();
}

export default function CreateDropPage() {
  const { publicKey, sendTransaction } = useWallet();
  const { connection } = useConnection();

  const [amount, setAmount] = useState("");
  const [password, setPassword] = useState("");
  const [asset, setAsset] = useState<Asset>("sol");
  const [depositMode, setDepositMode] = useState<DepositMode>("direct");
  const [enableRevoke, setEnableRevoke] = useState(false);
  const [stage, setStage] = useState<Stage>("input");
  const [claimCode, setClaimCode] = useState("");
  const [error, setError] = useState("");
  const [txSig, setTxSig] = useState("");
  const [receiptSaved, setReceiptSaved] = useState(false);
  const [relayerOnline, setRelayerOnline] = useState<boolean | null>(null);
  // USDC ATA state — null means "not yet probed" / no wallet; bigint amount
  // is the on-chain balance in base units. `ataExists=false` means probed
  // and missing (user has never received USDC on this wallet).
  const [usdcBalance, setUsdcBalance] = useState<bigint | null>(null);
  const [usdcAtaExists, setUsdcAtaExists] = useState<boolean | null>(null);

  useEffect(() => {
    checkRelayerHealth().then((online) => {
      setRelayerOnline(online);
      // Auto-select default deposit mode for SOL only. USDC always forces
      // "direct" because relayer-fronted SPL deposits / SPL pool are not
      // shipped yet. #19 gate: also stay "direct" until the relayer-fronted SOL
      // modes have a frontend nonce/memo client.
      setDepositMode(SOL_RELAYER_DEPOSITS_ENABLED && online ? "private" : "direct");
    });
  }, []);

  // Whenever asset flips to USDC (or the connected wallet changes), refresh
  // the USDC ATA state. Asset==="sol" leaves the state alone — cheap to keep.
  useEffect(() => {
    if (asset !== "usdc" || !publicKey) {
      setUsdcBalance(null);
      setUsdcAtaExists(null);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const ata = getAssociatedTokenAddressSync(DEVNET_USDC_MINT, publicKey);
        const acct = await getAccount(connection, ata, "confirmed");
        if (cancelled) return;
        setUsdcAtaExists(true);
        setUsdcBalance(acct.amount);
      } catch (err) {
        if (cancelled) return;
        if (
          err instanceof TokenAccountNotFoundError ||
          err instanceof TokenInvalidAccountOwnerError
        ) {
          setUsdcAtaExists(false);
          setUsdcBalance(0n);
        } else {
          // Network blip — leave state as "unknown" so we don't surface a
          // misleading "no USDC" message; the deposit handler will re-probe.
          setUsdcAtaExists(null);
          setUsdcBalance(null);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [asset, publicKey, connection]);

  // Asset-flip side effects: USDC mode is direct-only with no revoke. Flip
  // both back/off when user switches modes so leftover UI selections never
  // produce a bad submit.
  useEffect(() => {
    if (asset === "usdc") {
      setDepositMode("direct");
      setEnableRevoke(false);
    } else if (asset === "sol") {
      // Restore relayer-aware default if relayer is up. #19 gate: stays "direct"
      // until the relayer-fronted SOL modes have a frontend nonce/memo client.
      setDepositMode(SOL_RELAYER_DEPOSITS_ENABLED && relayerOnline ? "private" : "direct");
    }
  }, [asset, relayerOnline]);

  /**
   * USDC deposit path. Separate from the SOL handler so the SOL code path
   * stays byte-identical to its pre-USDC form — no shared mutation, no
   * shared early-return logic. Only DIRECT mode (user-signed); private/pool
   * SPL deposits are not shipped yet, and revoke is SOL-only on-chain.
   */
  const handleCreateDropUsdc = async () => {
    if (!publicKey || !sendTransaction) return;

    if (usdcAtaExists === false) {
      setError(
        "You don't have any USDC. Get devnet USDC from https://faucet.circle.com/"
      );
      return;
    }

    let baseUnits: bigint;
    try {
      baseUnits = parseUsdcAmount(amount);
    } catch (e: any) {
      setError(e.message || "Invalid USDC amount");
      return;
    }
    if (baseUnits <= 0n) {
      setError("Enter a valid USDC amount");
      return;
    }
    if (baseUnits < USDC_MIN_DEPOSIT) {
      setError(`Minimum deposit: ${formatUsdc(USDC_MIN_DEPOSIT)} USDC`);
      return;
    }
    if (baseUnits > USDC_MAX_DEPOSIT) {
      setError(`Maximum deposit: ${formatUsdc(USDC_MAX_DEPOSIT)} USDC`);
      return;
    }
    if (usdcBalance !== null && baseUnits > usdcBalance) {
      setError(`Insufficient USDC balance: have ${formatUsdc(usdcBalance)} USDC`);
      return;
    }

    setStage("confirming");
    setError("");
    setReceiptSaved(false);

    try {
      await initPoseidon();

      const pwdBigint = password
        ? BigInt(
            "0x" +
              Array.from(new TextEncoder().encode(password))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("")
          )
        : undefined;

      const dropResult = prepareCreateDrop(baseUnits, pwdBigint);

      const userAta = getAssociatedTokenAddressSync(DEVNET_USDC_MINT, publicKey);
      const splDepositIx = buildCreateDropSplIx({
        user: publicKey,
        userAta,
        mint: DEVNET_USDC_MINT,
        leaf: dropResult.leaf,
        amount: baseUnits,
      });

      const tx = new Transaction().add(splDepositIx);
      const sig = await sendWithRetry({
        wallet: { sendTransaction },
        connection,
        transaction: tx,
      });

      // Snapshot the per-mint SPL tree post-deposit. The `MerkleTreeSpl`
      // struct differs from the SOL `MerkleTreeAccount` by an extra `mint`
      // pubkey after `vault`, so byte offsets shift by 32 and the lib helper
      // `snapshotTreeAccount` (which expects SOL layout) cannot be reused.
      // We build the same 672-byte snapshot blob (root + 20 filled_subtrees)
      // here so the claim page's `decodeTreeSnapshot` + `buildProofFromSnapshot`
      // work unchanged — they only care about the blob shape, not the
      // source-account layout.
      //
      // MerkleTreeSpl layout:
      //   8 (disc) + 32 (vault) + 32 (mint) + 4 (next_index)
      //   + 4 (root_history_index) + 32 (current_root)
      //   + 32*256 (root_history) + 32*20 (filled_subtrees)
      const SPL_NEXT_INDEX_OFFSET = 72;
      const SPL_ROOT_OFFSET = 80;
      const SPL_FILLED_SUBTREES_OFFSET = 8304;
      const MERKLE_DEPTH = 20;

      const [splTreePda] = getMerkleTreeSplPDA(DEVNET_USDC_MINT);
      const treeAccount = await connection.getAccountInfo(splTreePda);
      if (!treeAccount) throw new Error("SPL merkle tree account not found");

      const td = treeAccount.data;
      const nextIndex = new DataView(
        td.buffer,
        td.byteOffset,
        td.byteLength
      ).getUint32(SPL_NEXT_INDEX_OFFSET, true);
      const leafIndex = nextIndex - 1;

      const snapBuf = new Uint8Array(32 + MERKLE_DEPTH * 32);
      snapBuf.set(
        td.subarray(SPL_ROOT_OFFSET, SPL_ROOT_OFFSET + 32),
        0
      );
      for (let i = 0; i < MERKLE_DEPTH; i++) {
        snapBuf.set(
          td.subarray(
            SPL_FILLED_SUBTREES_OFFSET + i * 32,
            SPL_FILLED_SUBTREES_OFFSET + (i + 1) * 32
          ),
          32 + i * 32
        );
      }
      let bin = "";
      for (let i = 0; i < snapBuf.length; i++) {
        bin += String.fromCharCode(snapBuf[i]);
      }
      const pathSnapshot = btoa(bin)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

      const [splVault] = getSplVaultPDA();

      const code = await encodeClaimCode(
        {
          ...dropResult.claimPayload,
          leafIndex,
          vaultAddress: splVault.toBase58(),
          pathSnapshot,
          flavor: "standard",
          mint: DEVNET_USDC_MINT.toBase58(),
        },
        "devnet",
        "usdc",
        password || undefined
      );

      setClaimCode(code);
      setTxSig(sig);
      setStage("done");
    } catch (err: any) {
      console.error("Create USDC drop failed:", err.message);
      setError(err.message || "Transaction failed");
      setStage("error");
    }
  };

  const handleCreateDrop = async () => {
    if (!publicKey || !sendTransaction) return;

    const solAmount = parseFloat(amount);
    if (isNaN(solAmount) || solAmount <= 0) {
      setError("Enter a valid SOL amount");
      return;
    }
    if (solAmount < MIN_SOL) {
      setError(`Minimum deposit: ${MIN_SOL} SOL`);
      return;
    }
    if (solAmount > 100) {
      setError("Drop cap: 100 SOL maximum");
      return;
    }

    if (enableRevoke && depositMode !== "direct") {
      setError("Revoke option requires direct deposit (your wallet must sign as depositor).");
      return;
    }
    if (depositMode === "pool" && !relayerOnline) {
      setError("Max privacy mode requires the relayer to be online.");
      return;
    }
    if (!SOL_RELAYER_DEPOSITS_ENABLED && depositMode !== "direct") {
      // #19 gate (defense in depth): the relayer-fronted SOL modes need a
      // per-deposit nonce/memo the frontend doesn't send yet. The UI hides these
      // modes; this guard ensures a stale selection can never POST to the relayer.
      setDepositMode("direct");
      setError("Private / Max-Privacy SOL deposits are temporarily disabled — switched to direct. Please retry.");
      return;
    }

    setStage("confirming");
    setError("");
    setReceiptSaved(false);

    try {
      const lamports = BigInt(Math.round(solAmount * 1e9));

      // Initialize Poseidon hasher
      await initPoseidon();

      // Generate cryptographic values and compute leaf + commitment
      const pwdBigint = password
        ? BigInt(
            "0x" +
              Array.from(new TextEncoder().encode(password))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("")
          )
        : undefined;

      const dropResult = prepareCreateDrop(lamports, pwdBigint);

      // Pool mode uses its own preimage — pool_secret, pool_nullifier, pool_blinding.
      // The pool leaf itself is constructed on-chain using the verified amount.
      const poolSecret = randomFieldElement();
      const poolNullifier = randomFieldElement();
      const poolBlinding = randomFieldElement();

      // PDAs
      const [vault] = getVaultPDA();
      const [merkleTree] = getMerkleTreePDA(vault);
      const [treasury] = getTreasuryPDA();
      const [notePoolTree] = getNotePoolTreePDA(vault);

      let sig: string;

      if (depositMode === "pool") {
        // Max privacy: relayer calls create_drop_to_pool. User's wallet only
        // appears as the source of a plain system transfer; the pool entry
        // and the eventual pool claim are unlinkable to them.
        const relayerPubkey = await fetch(`${RELAYER_URL}/health`)
          .then(r => r.json())
          .then(d => d.relayerPubkey);
        if (!relayerPubkey) throw new Error("Relayer not available");

        const { PublicKey: PK } = await import("@solana/web3.js");
        // #19: per-deposit single-use nonce (32 bytes -> 64 lowercase hex),
        // committed in an SPL Memo on the transfer. The relayer (verify-deposit.ts)
        // requires exactly one transfer + one memo(nonce), TOLERATES benign
        // ComputeBudget ixs (relayer fix #38), and rejects any other program / ALT.
        const nonce = Array.from(
          crypto.getRandomValues(new Uint8Array(32)),
          (b) => b.toString(16).padStart(2, "0")
        ).join("");
        const transferIx = SystemProgram.transfer({
          fromPubkey: publicKey,
          toPubkey: new PK(relayerPubkey),
          lamports: Number(lamports),
        });
        const memoIx = new TransactionInstruction({
          programId: new PK("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
          keys: [],
          data: Buffer.from(nonce, "utf8"),
        });
        // Defense-in-depth (#38): prepend explicit ComputeBudget ixs so the tx's
        // instruction set is deterministic — wallets are less likely to auto-inject
        // priority-fee ixs when they are already present. The relayer tolerates
        // ComputeBudget ixs regardless (verify-deposit.ts) — that's the real fix.
        const cuLimitIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 50_000 });
        const cuPriceIx = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000 });
        const transferTx = new Transaction().add(cuLimitIx, cuPriceIx, transferIx, memoIx);
        const depositSig = await sendTransaction(transferTx, connection);
        await connection.confirmTransaction(depositSig, "confirmed");

        const poolParams = new Uint8Array(96);
        poolParams.set(bigintToBytes32BE(poolSecret), 0);
        poolParams.set(bigintToBytes32BE(poolNullifier), 32);
        poolParams.set(bigintToBytes32BE(poolBlinding), 64);

        const resp = await fetch(`${RELAYER_URL}/api/relay/create-drop-to-pool`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            amount: lamports.toString(),
            poolParams: Array.from(poolParams),
            depositTx: depositSig,
            payer: publicKey.toBase58(), // #19: declared transfer source
            nonce,                        // #19: single-use nonce, === the memo content
          }),
        });
        const result = await resp.json();
        if (!resp.ok) throw new Error(result.error || "Pool deposit relay failed");
        sig = result.signature;
      } else if (depositMode === "private") {
        // Private deposit: send SOL to relayer wallet, relayer calls create_drop
        // Step 1: Transfer SOL to relayer via normal system transfer
        const relayerPubkey = await fetch(`${RELAYER_URL}/health`)
          .then(r => r.json())
          .then(d => d.relayerPubkey);

        if (!relayerPubkey) throw new Error("Relayer not available");

        const { PublicKey: PK } = await import("@solana/web3.js");
        // #19: per-deposit single-use nonce (32 bytes -> 64 lowercase hex),
        // committed in an SPL Memo on the transfer. The relayer (verify-deposit.ts)
        // requires exactly one transfer + one memo(nonce), TOLERATES benign
        // ComputeBudget ixs (relayer fix #38), and rejects any other program / ALT.
        const nonce = Array.from(
          crypto.getRandomValues(new Uint8Array(32)),
          (b) => b.toString(16).padStart(2, "0")
        ).join("");
        const transferIx = SystemProgram.transfer({
          fromPubkey: publicKey,
          toPubkey: new PK(relayerPubkey),
          lamports: Number(lamports),
        });
        const memoIx = new TransactionInstruction({
          programId: new PK("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
          keys: [],
          data: Buffer.from(nonce, "utf8"),
        });
        // Defense-in-depth (#38): prepend explicit ComputeBudget ixs so the tx's
        // instruction set is deterministic — wallets are less likely to auto-inject
        // priority-fee ixs when they are already present. The relayer tolerates
        // ComputeBudget ixs regardless (verify-deposit.ts) — that's the real fix.
        const cuLimitIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 50_000 });
        const cuPriceIx = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000 });
        const transferTx = new Transaction().add(cuLimitIx, cuPriceIx, transferIx, memoIx);
        const depositSig = await sendTransaction(transferTx, connection);
        await connection.confirmTransaction(depositSig, "confirmed");

        // Step 2: Tell relayer to call create_drop
        const resp = await fetch(`${RELAYER_URL}/api/relay/create-drop`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            // Audit 06 L-01: create_drop no longer takes amount_commitment / password_hash.
            leaf: Array.from(dropResult.leaf),
            amount: lamports.toString(),
            depositTx: depositSig,
            payer: publicKey.toBase58(), // #19: declared transfer source
            nonce,                        // #19: single-use nonce, === the memo content
          }),
        });
        const result = await resp.json();
        if (!resp.ok) throw new Error(result.error || "Deposit relay failed");
        sig = result.signature;
      } else {
        // Direct deposit: user calls create_drop directly
        const amountBuf = new Uint8Array(8);
        new DataView(amountBuf.buffer).setBigUint64(0, lamports, true);

        // Audit 06 L-01: create_drop instruction data is now just leaf + amount.
        const ixData = new Uint8Array(8 + 32 + 8);
        let offset = 0;
        ixData.set(CREATE_DROP_DISCRIMINATOR, offset); offset += 8;
        ixData.set(dropResult.leaf, offset); offset += 32;
        ixData.set(amountBuf, offset);

        const keys = [
          { pubkey: vault, isSigner: false, isWritable: true },
          { pubkey: merkleTree, isSigner: false, isWritable: true },
          { pubkey: treasury, isSigner: false, isWritable: true },
          { pubkey: publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ];

        if (enableRevoke) {
          // 7-account path: append depositor + deposit_receipt PDA.
          // Depositor == connected wallet (I-02: never let another signer be depositor).
          const [receiptPda] = getReceiptPDA(dropResult.leaf);
          keys.push(
            { pubkey: publicKey, isSigner: true, isWritable: true },
            { pubkey: receiptPda, isSigner: false, isWritable: true },
          );
        }

        const createDropIx = new TransactionInstruction({
          programId: PROGRAM_ID,
          keys,
          data: Buffer.from(ixData),
        });

        const tx = new Transaction().add(createDropIx);
        sig = await sendWithRetry({
          wallet: { sendTransaction },
          connection,
          transaction: tx,
        });
      }

      // Read leaf index + snapshot the appropriate tree (main vs note pool
      // depending on mode). Same on-chain struct layout, different PDA.
      const treePdaForMode = depositMode === "pool" ? notePoolTree : merkleTree;
      const treeAccount = await connection.getAccountInfo(treePdaForMode);
      if (!treeAccount) throw new Error("Failed to read tree account");

      const nextIndex = new DataView(
        treeAccount.data.buffer,
        treeAccount.data.byteOffset
      ).getUint32(8 + 32, true);
      const leafIndex = nextIndex - 1;
      const pathSnapshot = snapshotTreeAccount(treeAccount.data);

      // Encode claim code. For pool flavor, the (secret, nullifier, blinding)
      // fields carry pool_secret / pool_nullifier / pool_blinding — the
      // same semantic slot, reused for the pool leaf preimage.
      const claimPayloadForMode =
        depositMode === "pool"
          ? {
              secret: poolSecret,
              nullifier: poolNullifier,
              amount: lamports,
              blindingFactor: poolBlinding,
            }
          : dropResult.claimPayload;

      const code = await encodeClaimCode(
        {
          ...claimPayloadForMode,
          leafIndex,
          vaultAddress: vault.toBase58(),
          pathSnapshot,
          flavor: depositMode === "pool" ? "pool" : "standard",
        },
        "devnet",
        "sol",
        password || undefined
      );

      if (enableRevoke) {
        saveReceipt({
          leafHex: bytesToHex(dropResult.leaf),
          leafIndex,
          amountLamports: lamports.toString(),
          depositor: publicKey.toBase58(),
          createdAt: Math.floor(Date.now() / 1000),
          cluster: "devnet",
          vaultAddress: vault.toBase58(),
          secretHex: bigintToHex32(dropResult.claimPayload.secret),
          nullifierHex: bigintToHex32(dropResult.claimPayload.nullifier),
          blindingHex: bigintToHex32(dropResult.claimPayload.blindingFactor),
          txSig: sig,
        });
        setReceiptSaved(true);
      }

      setClaimCode(code);
      setTxSig(sig);
      setStage("done");
    } catch (err: any) {
      console.error("Create drop failed:", err.message);
      setError(err.message || "Transaction failed");
      setStage("error");
    }
  };

  return (
    <div className="mx-auto w-full max-w-xl px-4 sm:px-6 pb-20" style={{ paddingTop: "80px" }}>
      <div className="mb-8">
        <p className="mb-2 font-mono text-[9px] tracking-[0.3em] text-[var(--accent-dim)]">
          OUTPUT // 0X01
        </p>
        <h1 className="font-mono text-[clamp(24px,4vw,36px)] font-light leading-[1.15] text-[var(--text)]">
          Create a<br />dead drop.
        </h1>
        <p className="mt-3 text-xs leading-relaxed text-[rgba(224,224,224,0.45)]">
          Deposit SOL or USDC into the Merkle vault. You will receive a claim code to share with anyone.
        </p>
      </div>

        {(stage === "input" || stage === "error") ? (
          <div className="space-y-4">
            {!publicKey && (
              <div className="arcade-panel">
                <div className="arcade-panel-body text-center text-sm text-[rgba(224,224,224,0.4)]">
                  Connect your wallet to create a drop.
                </div>
              </div>
            )}

            {publicKey && (
              <>
                {/* Asset selector */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header">
                    <span className="arcade-dot" />
                    <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">ASSET</span>
                  </div>
                  <div className="arcade-panel-body flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setAsset("sol");
                        setAmount("");
                        setError("");
                      }}
                      className={`flex-1 border-2 py-3 text-center transition-all !shadow-none ${
                        asset === "sol"
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      }`}
                    >
                      <span className={`font-mono text-[11px] tracking-[0.14em] font-semibold ${
                        asset === "sol" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                      }`}>SOL</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setAsset("usdc");
                        setAmount("");
                        setError("");
                      }}
                      className={`flex-1 border-2 py-3 text-center transition-all !shadow-none ${
                        asset === "usdc"
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      }`}
                    >
                      <span className={`font-mono text-[11px] tracking-[0.14em] font-semibold ${
                        asset === "usdc" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                      }`}>USDC</span>
                    </button>
                  </div>
                </div>

                {/* Amount field */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header justify-between">
                    <div className="flex items-center gap-3">
                      <span className="arcade-dot" />
                      <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">
                        AMOUNT ({asset === "usdc" ? "USDC" : "SOL"})
                      </span>
                    </div>
                    {asset === "usdc" && usdcAtaExists !== null && (
                      <span className="font-mono text-[8px] tracking-[0.12em] text-[rgba(224,224,224,0.4)]">
                        BALANCE: {usdcBalance !== null ? formatUsdc(usdcBalance) : "—"} USDC
                      </span>
                    )}
                  </div>
                  <div className="arcade-panel-body">
                    <input
                      type="number"
                      step={asset === "usdc" ? "0.01" : "0.001"}
                      min={asset === "usdc" ? "0.01" : MIN_SOL}
                      max={asset === "usdc" ? "100000" : "100"}
                      value={amount}
                      onChange={(e) => setAmount(e.target.value)}
                      placeholder="0.00"
                      className="w-full text-[var(--accent)] text-lg font-mono"
                    />
                    {asset === "usdc" && usdcAtaExists === false && (
                      <p className="mt-2 text-[10px] leading-relaxed text-[rgba(255,200,0,0.7)]">
                        You don't have any USDC. Get devnet USDC from{" "}
                        <a
                          href="https://faucet.circle.com/"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="underline text-[var(--accent)]"
                        >
                          faucet.circle.com
                        </a>
                        .
                      </p>
                    )}
                  </div>
                </div>

                {/* Password field */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header">
                    <span className="arcade-dot" />
                    <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">PASSWORD (OPTIONAL)</span>
                  </div>
                  <div className="arcade-panel-body">
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Leave empty for no password"
                      className="w-full text-sm font-mono"
                    />
                    <p className="mt-2 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                      If set, the recipient must enter this password to decrypt the claim code (client-side PBKDF2 + AES-256-GCM). Protection comes from the encrypted code, not the on-chain ZK proof — anyone who can decrypt the code can claim, so share it carefully.
                    </p>
                  </div>
                </div>

                {/* SOL-only deposit-method + revoke panels. USDC ships with
                    direct mode only (no relayer-fronted SPL deposits / SPL pool
                    on-chain) and no revoke (revoke_drop_spl doesn't exist). */}
                {asset === "sol" && (
                <>
                {/* Deposit mode */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header justify-between">
                    <div className="flex items-center gap-3">
                      <span className="arcade-dot" />
                      <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">DEPOSIT METHOD</span>
                    </div>
                    {relayerOnline !== null && (
                      <span className={`font-mono text-[8px] tracking-[0.12em] flex items-center gap-1.5 ${relayerOnline ? "text-[rgba(0,255,65,0.5)]" : "text-[rgba(224,224,224,0.25)]"}`}>
                        <span className={relayerOnline ? "arcade-dot" : "arcade-dot arcade-dot-off"} style={{ height: 5, width: 5 }} />
                        {relayerOnline ? "RELAYER: ONLINE" : "RELAYER: OFFLINE"}
                      </span>
                    )}
                  </div>
                  <div className="arcade-panel-body space-y-2">
                    <button
                      type="button"
                      onClick={() => setDepositMode("direct")}
                      className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                        depositMode === "direct"
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      }`}
                    >
                      <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                        depositMode === "direct"
                          ? "border-[var(--accent)]"
                          : "border-[rgba(224,224,224,0.2)]"
                      }`}>
                        {depositMode === "direct" && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                            depositMode === "direct" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                          }`}>DIRECT</span>
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                          Your wallet calls the program directly. Deposit amount is visible on-chain.
                        </p>
                      </div>
                    </button>
                    {/* #19 gate: relayer-fronted SOL deposit modes are hidden until the
                        frontend sends the per-deposit payer + nonce/memo the relayer requires. */}
                    {SOL_RELAYER_DEPOSITS_ENABLED && (
                    <>
                    <button
                      type="button"
                      onClick={() => relayerOnline && !enableRevoke && setDepositMode("private")}
                      disabled={!relayerOnline || enableRevoke}
                      className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                        depositMode === "private"
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      } ${(!relayerOnline || enableRevoke) ? "opacity-40 !cursor-not-allowed" : ""}`}
                    >
                      <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                        depositMode === "private"
                          ? "border-[var(--accent)]"
                          : "border-[rgba(224,224,224,0.2)]"
                      }`}>
                        {depositMode === "private" && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                            depositMode === "private" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                          }`}>PRIVATE DEPOSIT</span>
                          <span className="arcade-badge">RELAYER</span>
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                          SOL routes through the relayer. Your wallet never appears in the DarkDrop TX.
                        </p>
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => relayerOnline && !enableRevoke && setDepositMode("pool")}
                      disabled={!relayerOnline || enableRevoke}
                      className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                        depositMode === "pool"
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      } ${(!relayerOnline || enableRevoke) ? "opacity-40 !cursor-not-allowed" : ""}`}
                    >
                      <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                        depositMode === "pool"
                          ? "border-[var(--accent)]"
                          : "border-[rgba(224,224,224,0.2)]"
                      }`}>
                        {depositMode === "pool" && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                            depositMode === "pool" ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                          }`}>MAX PRIVACY</span>
                          <span className="arcade-badge">POOL</span>
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                          SOL enters the note pool directly. Second ZK layer hides the leaf → recipient link on top of the relayer hiding your wallet. No revoke option.
                        </p>
                      </div>
                    </button>
                    </>
                    )}
                  </div>
                </div>

                {depositMode === "pool" && (
                  <div className="border-2 border-[rgba(255,200,0,0.3)] bg-[rgba(255,200,0,0.04)] px-4 py-3">
                    <p className="font-mono text-[10px] leading-relaxed text-[rgba(255,200,0,0.85)]">
                      <span className="font-semibold tracking-[0.12em]">NO REVOKE PATH.</span>{" "}
                      <span className="text-[rgba(255,200,0,0.7)]">Pool deposits cannot be reclaimed. Lose the claim code and the SOL is permanently locked — no time-lock fallback. Only DIRECT deposits with the revoke option enabled below can be reclaimed after 30 days.</span>
                    </p>
                  </div>
                )}

                {/* Enable revoke */}
                <div className="arcade-panel">
                  <div className="arcade-panel-header">
                    <span className="arcade-dot" />
                    <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(224,224,224,0.3)]">REVOKE OPTION</span>
                  </div>
                  <div className="arcade-panel-body">
                    <button
                      type="button"
                      onClick={() => {
                        const next = !enableRevoke;
                        setEnableRevoke(next);
                        if (next) setDepositMode("direct");
                      }}
                      className={`flex w-full items-start gap-3 border-2 p-4 text-left transition-all !shadow-none ${
                        enableRevoke
                          ? "border-[var(--accent-dim)] bg-[rgba(0,255,65,0.04)]"
                          : "border-[var(--border-dim)] hover:border-[var(--border)]"
                      }`}
                    >
                      <span className={`mt-0.5 flex h-4 w-4 items-center justify-center border-2 ${
                        enableRevoke
                          ? "border-[var(--accent)]"
                          : "border-[rgba(224,224,224,0.2)]"
                      }`}>
                        {enableRevoke && <span className="block h-2 w-2 bg-[var(--accent)]" />}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono text-[10px] tracking-[0.12em] font-semibold ${
                            enableRevoke ? "text-[var(--accent)]" : "text-[rgba(224,224,224,0.5)]"
                          }`}>ENABLE REVOKE (30-DAY LOCK)</span>
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-[rgba(224,224,224,0.3)]">
                          Reclaim unclaimed drops after a 30-day time-lock. DIRECT-only — PRIVATE and MAX PRIVACY are disabled here because a receipt needs the depositor as on-chain signer, which is incompatible with relayer-only submission. Privacy cost: links your wallet to (leaf, amount) on-chain.
                        </p>
                      </div>
                    </button>
                  </div>
                </div>
                </>
                )}

                {error && (
                  <div className="border-2 border-[rgba(255,0,68,0.3)] bg-[rgba(255,0,68,0.04)] px-5 py-3 shadow-[2px_2px_0_rgba(255,0,68,0.2)]">
                    <p className="text-xs text-[var(--danger)] font-semibold">{error}</p>
                  </div>
                )}

                <button
                  onClick={asset === "usdc" ? handleCreateDropUsdc : handleCreateDrop}
                  disabled={!amount || (asset === "usdc" && usdcAtaExists === false)}
                  className="arcade-btn-primary w-full py-3.5 font-mono text-[10px] tracking-[0.2em]"
                >
                  {asset === "usdc"
                    ? "CREATE USDC DROP"
                    : depositMode === "pool"
                    ? "MAX PRIVACY DEPOSIT"
                    : depositMode === "private"
                    ? "PRIVATE DEPOSIT"
                    : enableRevoke
                    ? "CREATE DROP + RECEIPT"
                    : "CREATE DROP"}
                </button>
              </>
            )}
          </div>
        ) : stage === "confirming" ? (
          <div className="arcade-panel arcade-glow">
            <div className="arcade-panel-body p-8 text-center">
              <div className="text-[var(--accent)] animate-pulse text-sm mb-2 font-semibold">
                Confirming transaction...
              </div>
              <div className="text-[10px] text-[rgba(224,224,224,0.3)]">
                Approve the transaction in your wallet.
              </div>
            </div>
          </div>
        ) : stage === "done" ? (
          <div className="space-y-4">
            <div className="arcade-panel arcade-glow">
              <div className="arcade-panel-header justify-center">
                <span className="arcade-dot" />
                <span className="font-mono text-[9px] tracking-[0.28em] text-[rgba(0,255,65,0.6)]">DROP CREATED</span>
              </div>
              <div className="arcade-panel-body text-center">
                <p className="text-sm text-[rgba(224,224,224,0.5)]">{amount} {asset === "usdc" ? "USDC" : "SOL"} deposited to vault</p>
              </div>
            </div>

            <CodeDisplay code={claimCode} />

            {txSig && (
              <div className="text-center">
                <a
                  href={`https://solscan.io/tx/${txSig}?cluster=devnet`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-[10px] tracking-[0.1em] text-[rgba(0,255,65,0.5)] hover:text-[var(--accent)] transition-colors"
                >
                  VIEW TRANSACTION ON SOLSCAN
                </a>
              </div>
            )}

            <div className="border-2 border-[rgba(255,0,68,0.2)] bg-[rgba(255,0,68,0.02)] px-5 py-3">
              <p className="text-[10px] leading-relaxed text-[rgba(224,224,224,0.4)]">
                Share this code with the recipient. Anyone with the code can claim the funds{password ? " (password required)" : ""}. Store it securely.
              </p>
            </div>

            {receiptSaved && (
              <div className="border-2 border-[rgba(0,255,65,0.2)] bg-[rgba(0,255,65,0.03)] px-5 py-3">
                <p className="text-[10px] leading-relaxed text-[rgba(224,224,224,0.55)]">
                  Revoke receipt saved to this browser. If the drop is not claimed, you can reclaim it after 30 days from <a href="/drop/manage" className="text-[var(--accent)] hover:underline">/drop/manage</a>. The preimage lives only in this browser — back it up if you switch devices.
                </p>
              </div>
            )}

            <button
              onClick={() => {
                setStage("input");
                setAmount("");
                setPassword("");
                setClaimCode("");
                setReceiptSaved(false);
              }}
              className="arcade-btn-ghost w-full py-3 font-mono text-[10px] tracking-[0.15em]"
            >
              CREATE ANOTHER
            </button>
          </div>
        ) : null}
    </div>
  );
}
