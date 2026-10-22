// The `local` key provider (spec section 4.3): a 32-byte key you hold
// yourself and set on the platform as KEYSEAL_KEY. No cloud account, but
// nothing outside the platform stands between its env store and your
// secrets: whoever reads KEYSEAL_KEY and a bundle reads every value, with no
// audit log and no way to revoke it short of a new key. See
// spec/THREAT_MODEL.md.

import { field, type Rng, secureRandom, type WebCryptoKey } from "./crypto.ts";
import {
  b64uDecode,
  b64uEncode,
  type Bytes,
  concat,
  own,
  utf8,
} from "./encoding.ts";
import { KeysealError } from "./errors.ts";
import type { GeneratedDataKey, KeyContext, KeyProvider } from "./keys.ts";

const subtle = globalThis.crypto.subtle;

const PREFIX = "keyseal_local_";
const KEY_RE = /^keyseal_local_[A-Za-z0-9_-]{43}$/;
const NONCE_BYTES = 12;
const WRAPPED_BYTES = NONCE_BYTES + 32 + 16;

export interface LocalKeyOptions {
  /**
   * Local keys to try, as made by `generateLocalKey`. A string may hold
   * several, separated by whitespace or commas. Defaults to KEYSEAL_KEY.
   */
  keys?: string | readonly string[];
  /** Randomness override, for reproducible test vectors only. */
  rng?: Rng;
}

/** A new local key: "keyseal_local_" and 32 random bytes in base64url. */
export function generateLocalKey(rng: Rng = secureRandom): string {
  return PREFIX + b64uEncode(rng(32));
}

// Error messages never include the key itself.
function decodeKey(key: string): Bytes {
  const raw = KEY_RE.test(key) ? b64uDecode(key.slice(PREFIX.length)) : null;
  if (raw?.length !== 32) {
    throw new KeysealError(
      "invalid_argument",
      'a local key is "keyseal_local_" followed by 43 base64url characters'
    );
  }
  return raw;
}

interface Unlocked {
  id: string;
  wrap: WebCryptoKey;
}

async function unlock(key: string): Promise<Unlocked> {
  const raw = decodeKey(key);
  try {
    const ikm = await subtle.importKey("raw", raw, "HKDF", false, [
      "deriveBits",
      "deriveKey",
    ]);
    const salt = new Uint8Array(0);
    const id = await subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: utf8("keyseal/v1/local-id"),
      },
      ikm,
      128
    );
    const wrap = await subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: utf8("keyseal/v1/local-wrap"),
      },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    return { id: b64uEncode(new Uint8Array(id)), wrap };
  } finally {
    raw.fill(0);
  }
}

/** The id bundles sealed with this key store as `key.keyId`. Not secret. */
export async function localKeyId(key: string): Promise<string> {
  return (await unlock(key)).id;
}

function wrapAad(keyId: string, ctx: KeyContext): Bytes {
  return concat(
    field("keyseal/v1/local-wrap"),
    field(keyId),
    field(ctx.bundleId),
    field(ctx.env),
    field(String(ctx.epoch))
  );
}

function envKeys(): string | undefined {
  const g = globalThis as {
    process?: { env?: Record<string, string | undefined> };
  };
  return g.process?.env?.KEYSEAL_KEY;
}

function splitKeys(keys: string | readonly string[] | undefined): string[] {
  const list = typeof keys === "string" ? [keys] : (keys ?? []);
  return list.flatMap((k) => k.split(/[\s,]+/)).filter(Boolean);
}

/**
 * A key provider for bundles sealed with a local key. Every key is checked
 * when the provider is created, so a malformed KEYSEAL_KEY fails at startup.
 */
export function localKey(opts: LocalKeyOptions = {}): KeyProvider {
  const specs = splitKeys(opts.keys ?? envKeys());
  for (const k of specs) decodeKey(k).fill(0);
  const rng = opts.rng ?? secureRandom;
  let unlocked: Promise<Unlocked[]> | undefined;

  async function find(keyId: string): Promise<WebCryptoKey> {
    unlocked ??= Promise.all(specs.map(unlock));
    const match = (await unlocked).find((u) => u.id === keyId);
    if (!match) {
      throw new KeysealError(
        "key_unavailable",
        specs.length === 0
          ? `no local key: set KEYSEAL_KEY to the key for ${keyId}`
          : `none of the local keys supplied is ${keyId}`
      );
    }
    return match.wrap;
  }

  return {
    name: "local",

    async generateDataKey(
      keyId: string,
      ctx: KeyContext
    ): Promise<GeneratedDataKey> {
      const wrap = await find(keyId);
      const plaintext = rng(32);
      const nonce = rng(NONCE_BYTES);
      const ct = await subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: wrapAad(keyId, ctx),
          tagLength: 128,
        },
        wrap,
        plaintext
      );
      return { plaintext, wrapped: concat(nonce, new Uint8Array(ct)), keyId };
    },

    async decryptDataKey(
      keyId: string,
      wrapped: Uint8Array,
      ctx: KeyContext
    ): Promise<Bytes> {
      const wrap = await find(keyId);
      if (wrapped.length !== WRAPPED_BYTES) {
        throw new KeysealError(
          "key_unavailable",
          "key.wrapped is not a locally wrapped data key"
        );
      }
      const w = own(wrapped);
      try {
        const pt = await subtle.decrypt(
          {
            name: "AES-GCM",
            iv: w.slice(0, NONCE_BYTES),
            additionalData: wrapAad(keyId, ctx),
            tagLength: 128,
          },
          wrap,
          w.slice(NONCE_BYTES)
        );
        return new Uint8Array(pt);
      } catch (cause) {
        // The key id matched, so the wrapped key or its context was edited.
        throw new KeysealError(
          "key_unavailable",
          "the local key could not unwrap the data key: the bundle's id, environment, epoch or wrapped key was changed",
          { cause }
        );
      }
    },
  };
}
