export const RELAYER_URL = process.env.NEXT_PUBLIC_RELAYER_URL || "http://localhost:3001";
export const RELAYER_FEE_BPS = 50;

export async function checkRelayerHealth(): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${RELAYER_URL}/health`, { signal: controller.signal });
    clearTimeout(timeout);
    return res.ok;
  } catch {
    return false;
  }
}
