// WebCrypto primitives for format v1: HKDF key derivation (section 4.2),
// AES-256-GCM value encryption (section 5) and the bundle MAC (section 6).

import {
  b64uDecode,
  b64uEncode,
  type Bytes,
  concat,
  fromUtf8,
  uint32be,
  utf8,
} from "./encoding.ts";
import { KeysealError } from "./errors.ts";
import { type Bundle, MAX_VALUE_BYTES, sortedNames } from "./format.ts";

const subtle = globalThis.crypto.subtle;

export const DATA_KEY_BYTES = 32;
const NONCE_BYTES = 12;

/** Source of random bytes. Swappable only so test vectors are reproducible. */
export type Rng = (n: number) => Bytes;

export const secureRandom: Rng = (n) =>
  globalThis.crypto.getRandomValues(new Uint8Array(n));

/**
 * A WebCrypto key, named through `crypto.subtle` so the published types work
 * with the DOM lib, @types/node, Deno and Workers alike.
 */
export type WebCryptoKey = Awaited<
  ReturnType<typeof globalThis.crypto.subtle.importKey>
>;

/** Non-extractable keys derived from one bundle's data key. */
export interface BundleKeys {
  readonly enc: WebCryptoKey;
  readonly mac: WebCryptoKey;
}

export async function deriveKeys(
  dataKey: Bytes,
  bundleId: string
): Promise<BundleKeys> {
  if (dataKey.length !== DATA_KEY_BYTES) {
    throw new KeysealError(
      "key_unavailable",
      `data key must be ${DATA_KEY_BYTES} bytes`
    );
  }
  const ikm = await subtle.importKey("raw", dataKey, "HKDF", false, [
    "deriveKey",
  ]);
  const salt = utf8(bundleId);
  const enc = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8("keyseal/v1/enc") },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const mac = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8("keyseal/v1/mac") },
    ikm,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign", "verify"]
  );
  return { enc, mac };
}

export type Slot = "current" | "previous";

export function valueAad(
  bundleId: string,
  env: string,
  name: string,
  v: number,
  slot: Slot
): Bytes {
  return utf8(
    ["keyseal/v1/value", bundleId, env, name, String(v), slot].join("\0")
  );
}

export async function encryptValue(
  keys: BundleKeys,
  aad: Bytes,
  plaintext: string,
  rng: Rng
): Promise<string> {
  const pt = utf8(plaintext);
  if (pt.length > MAX_VALUE_BYTES) {
    throw new KeysealError(
      "invalid_argument",
      `secret values are limited to ${MAX_VALUE_BYTES} bytes`
    );
  }
  const nonce = rng(NONCE_BYTES);
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
    keys.enc,
    pt
  );
  return b64uEncode(concat(nonce, new Uint8Array(ct)));
}

export async function decryptValue(
  keys: BundleKeys,
  aad: Bytes,
  value: string,
  where: string
): Promise<string> {
  const raw = b64uDecode(value);
  if (raw === null || raw.length < NONCE_BYTES + 16) {
    throw new KeysealError("decrypt_failed", `${where} is malformed`);
  }
  try {
    const pt = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: raw.slice(0, NONCE_BYTES),
        additionalData: aad,
        tagLength: 128,
      },
      keys.enc,
      raw.slice(NONCE_BYTES)
    );
    return fromUtf8(new Uint8Array(pt));
  } catch (cause) {
    throw new KeysealError("decrypt_failed", `${where} failed to decrypt`, {
      cause,
    });
  }
}

/** A length-prefixed transcript field (spec section 6). */
export function field(s: string): Bytes {
  const b = utf8(s);
  return concat(uint32be(b.length), b);
}

/** The MAC input, field by field, exactly as spec section 6 lists it. */
export function macTranscript(b: Bundle): Bytes {
  const parts: Bytes[] = [
    field("keyseal/v1/bundle"),
    field(b.id),
    field(b.env),
    field(String(b.version)),
    field(b.updatedAt),
    field(b.key.provider),
    field(b.key.keyId),
    field(String(b.key.epoch)),
    field(b.key.wrapped),
    field(String(b.secrets.size)),
  ];
  for (const name of sortedNames(b.secrets)) {
    const e = b.secrets.get(name);
    if (!e) continue;
    parts.push(
      field(name),
      field(String(e.v)),
      field(e.rotatedAt),
      field(e.value)
    );
    if (e.previous) {
      parts.push(
        field("1"),
        field(String(e.previous.v)),
        field(e.previous.expiresAt),
        field(e.previous.value)
      );
    } else {
      parts.push(field("0"));
    }
  }
  return concat(...parts);
}

export async function computeMac(keys: BundleKeys, b: Bundle): Promise<string> {
  const sig = await subtle.sign("HMAC", keys.mac, macTranscript(b));
  return b64uEncode(new Uint8Array(sig));
}

export async function verifyMac(keys: BundleKeys, b: Bundle): Promise<void> {
  const mac = b64uDecode(b.mac);
  // subtle.verify compares in constant time.
  const ok =
    mac !== null &&
    mac.length === 32 &&
    (await subtle.verify("HMAC", keys.mac, mac, macTranscript(b)));
  if (!ok) {
    throw new KeysealError(
      "mac_mismatch",
      "bundle MAC does not verify: the file was modified, or this is the wrong key"
    );
  }
}
