// Byte helpers built on web standards only (atob/btoa, TextEncoder), so the
// core runs unchanged on Node, Bun, Deno and edge runtimes.

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export type Bytes = Uint8Array<ArrayBuffer>;

export function utf8(s: string): Bytes {
  return encoder.encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function b64uEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const B64U = /^[A-Za-z0-9_-]*$/;

/**
 * Strict base64url decode: no padding, no foreign characters, and the input
 * must be the canonical encoding of its bytes (no stray trailing bits).
 * Returns null when any of that fails.
 */
export function b64uDecode(s: string): Bytes | null {
  if (!B64U.test(s) || s.length % 4 === 1) return null;
  const padded =
    s.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (s.length % 4)) % 4);
  let bin: string;
  try {
    bin = atob(padded);
  } catch {
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return b64uEncode(out) === s ? out : null;
}

export function concat(...parts: Uint8Array[]): Bytes {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function uint32be(n: number): Bytes {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Copy into a fresh ArrayBuffer-backed array (WebCrypto wants one). */
export function own(b: Uint8Array): Bytes {
  const out = new Uint8Array(b.length);
  out.set(b);
  return out;
}

/** RFC 3339 UTC with whole seconds, the only timestamp form in a bundle. */
export function formatTime(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}
