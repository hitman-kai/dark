#!/usr/bin/env node
/**
 * DarkDrop V4 — Vault bootstrap (Audit 06 M-03)
 *
 * `initialize_vault` has NO constraint on which signer becomes the authority —
 * first caller after a fresh deploy wins and gains admin_sweep / pause /
 * rotation rights. The mitigation is process, not code: deploy and initialize
 * MUST be a tightly-sequenced operation by the deployer, and the result MUST be
 * verified. This script enforces that:
 *
 *   1. If the vault PDA does not exist yet → it submits initialize_vault from
 *      the deployer key, then re-reads the account and asserts the authority is
 *      the deployer.
 *   2. If the vault PDA already exists → it does NOT submit. It reads the stored
 *      authority and EXITS NON-ZERO if that authority is anyone other than the
 *      deployer key running this script (i.e. someone front-ran the init —
 *      see the runbook in CONTRIBUTING.md for recovery via the program upgrade
 *      authority).
 *
 * Usage:
 *   solana program deploy target/deploy/darkdrop.so --program-id <KEYPAIR>
 *   PROGRAM_ID=<deployed id> node scripts/initialize.js     # run IMMEDIATELY after deploy
 *
 * Env:
 *   RPC_URL    (default devnet)
 *   PROGRAM_ID (default: the deployed devnet address below)
 *   KEYPAIR    (default: ~/.config/solana/id.json) — must be the deployer key
 *   DROP_CAP   (default: 100 SOL, in lamports)
 */

const {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} = require("@solana/web3.js");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey(
  process.env.PROGRAM_ID || "GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU"
);
const KEYPAIR_PATH =
  process.env.KEYPAIR || path.join(require("os").homedir(), ".config/solana/id.json");
const DROP_CAP = BigInt(process.env.DROP_CAP || 100 * LAMPORTS_PER_SOL);

// Vault account layout: 8 (discriminator) + 1 (bump) + 32 (authority) + ...
// The deploy-time invariant we verify is that authority == deployer key.
const AUTHORITY_OFFSET = 9;

function getDiscriminator(name) {
  return crypto.createHash("sha256").update(`global:${name}`).digest().slice(0, 8);
}

function loadKeypair(p) {
  const secret = JSON.parse(fs.readFileSync(p, "utf8"));
  return Keypair.fromSecretKey(Uint8Array.from(secret));
}

const BPF_UPGRADEABLE_LOADER = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111"
);

// Read the program's upgrade authority from its ProgramData account.
// Returns the authority PublicKey, or null if the program is immutable /
// not an upgradeable program. ProgramData layout: 4-byte enum tag (3) +
// 8-byte slot + 1-byte Option discriminator + 32-byte authority (if Some).
async function getProgramUpgradeAuthority(connection, programId) {
  const [programData] = PublicKey.findProgramAddressSync(
    [programId.toBytes()],
    BPF_UPGRADEABLE_LOADER
  );
  const info = await connection.getAccountInfo(programData);
  if (!info) return null; // not an upgradeable program (or not deployed)
  const hasAuthority = info.data[12] === 1;
  if (!hasAuthority) return null; // immutable
  return new PublicKey(info.data.subarray(13, 45));
}

async function main() {
  const connection = new Connection(RPC_URL, "confirmed");
  const deployer = loadKeypair(KEYPAIR_PATH);

  const [vault] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);
  const [merkleTree] = PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree"), vault.toBytes()],
    PROGRAM_ID
  );
  const [treasury] = PublicKey.findProgramAddressSync([Buffer.from("treasury")], PROGRAM_ID);

  console.log(`Program:  ${PROGRAM_ID.toBase58()}`);
  console.log(`Deployer: ${deployer.publicKey.toBase58()}`);
  console.log(`Vault:    ${vault.toBase58()}`);

  // Audit 06 M-03: refuse to initialize unless the deployer key running this
  // script also holds the program's upgrade authority. This ties initialization
  // to whoever actually controls the program, closing the first-caller-wins race
  // (a front-runner who lands initialize_vault first would NOT hold the upgrade
  // authority, so legitimate ownership is verifiable).
  const upgradeAuthority = await getProgramUpgradeAuthority(connection, PROGRAM_ID);
  if (upgradeAuthority === null) {
    console.error(
      "FATAL: program has no upgrade authority (immutable or not an upgradeable\n" +
        "program). Cannot verify the deployer controls it. Aborting — initialize\n" +
        "only as part of a deploy you control."
    );
    process.exit(1);
  }
  if (!upgradeAuthority.equals(deployer.publicKey)) {
    console.error(
      "\nFATAL: program upgrade authority does not match this deployer key:\n" +
        `  upgrade authority: ${upgradeAuthority.toBase58()}\n` +
        `  deployer key:      ${deployer.publicKey.toBase58()}\n\n` +
        "Run this script with the keypair that deployed the program."
    );
    process.exit(1);
  }
  console.log(`Upgrade authority matches deployer ✅`);

  const existing = await connection.getAccountInfo(vault);
  if (existing) {
    // Already initialized — do NOT re-init. Verify who owns it.
    if (!existing.owner.equals(PROGRAM_ID)) {
      console.error(
        `FATAL: vault PDA exists but is owned by ${existing.owner.toBase58()}, not the program. Aborting.`
      );
      process.exit(1);
    }
    const authority = new PublicKey(
      existing.data.subarray(AUTHORITY_OFFSET, AUTHORITY_OFFSET + 32)
    );
    if (authority.equals(deployer.publicKey)) {
      console.log("Vault already initialized by this deployer key. Nothing to do. ✅");
      return;
    }
    console.error(
      "\nFATAL: vault is ALREADY initialized by an UNEXPECTED authority:\n" +
        `  stored authority: ${authority.toBase58()}\n` +
        `  deployer key:     ${deployer.publicKey.toBase58()}\n\n` +
        "This almost certainly means the initialize_vault call was front-run on a\n" +
        "fresh deploy (Audit 06 M-03). DO NOT proceed. If you still hold the program\n" +
        "upgrade authority, follow the recovery runbook in CONTRIBUTING.md\n" +
        "(close + redeploy before anything relies on this deployment)."
    );
    process.exit(1);
  }

  // Fresh deploy — initialize now, from the deployer key.
  console.log("Vault not initialized. Submitting initialize_vault from deployer key…");
  const dropCapBuf = Buffer.alloc(8);
  dropCapBuf.writeBigUInt64LE(DROP_CAP);

  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: merkleTree, isSigner: false, isWritable: true },
      { pubkey: treasury, isSigner: false, isWritable: true },
      { pubkey: deployer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([getDiscriminator("initialize_vault"), dropCapBuf]),
  });

  const sig = await sendAndConfirmTransaction(connection, new Transaction().add(ix), [deployer]);
  console.log(`initialize_vault TX: ${sig}`);

  // Verify the authority landed as the deployer (defense against a race that
  // confirmed between our existence check and our TX).
  const after = await connection.getAccountInfo(vault);
  const authority = new PublicKey(after.data.subarray(AUTHORITY_OFFSET, AUTHORITY_OFFSET + 32));
  if (!authority.equals(deployer.publicKey)) {
    console.error(
      `FATAL: post-init authority is ${authority.toBase58()}, not the deployer. ` +
        "A race was lost. Follow the recovery runbook in CONTRIBUTING.md."
    );
    process.exit(1);
  }
  console.log("Vault initialized and authority verified as deployer. ✅");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
