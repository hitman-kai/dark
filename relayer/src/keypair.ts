import { Keypair } from "@solana/web3.js";
import { config } from "./config";
import fs from "fs";
import os from "os";

export function loadRelayerKeypair(): Keypair {
  const keypairPath = config.keypairPath.replace("~", os.homedir());
  const secretKey = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
  return Keypair.fromSecretKey(new Uint8Array(secretKey));
}
