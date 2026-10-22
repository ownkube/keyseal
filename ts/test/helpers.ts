import { BundleEditor } from "../src/bundle.ts";
import type { KeyProvider } from "../src/keys.ts";
import { testKeys } from "../src/testing.ts";

export const T0: number = Date.parse("2026-10-22T12:00:00Z");
export const HOUR = 3_600_000;

export const DATA_KEY: Uint8Array = Uint8Array.from(
  { length: 32 },
  (_, i) => i
);

export function provider(): KeyProvider {
  return testKeys(DATA_KEY);
}

/** A mutable clock for editors. */
export function clock(start: number = T0): {
  now: () => number;
  advance: (ms: number) => void;
} {
  let t = start;
  return {
    now: () => t,
    advance: (ms) => {
      t += ms;
    },
  };
}

/** Seal a new bundle holding `secrets`. */
export async function sealed(
  secrets: Record<string, string>,
  opts: { env?: string; now?: () => number } = {}
): Promise<string> {
  const ed = await BundleEditor.create({
    env: opts.env ?? "production",
    keyId: "test-key",
    provider: provider(),
    ...(opts.now ? { now: opts.now } : {}),
  });
  for (const [k, v] of Object.entries(secrets)) await ed.set(k, v);
  return ed.seal();
}
