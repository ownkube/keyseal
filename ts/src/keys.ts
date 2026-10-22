import type { Bytes } from "./encoding.ts";

/** What a wrapped data key is bound to (spec section 4.1). */
export interface KeyContext {
  bundleId: string;
  env: string;
  /** Increments on every rekey, so old data keys can be denied in IAM. */
  epoch: number;
}

export interface GeneratedDataKey {
  /** 32 random bytes. Callers derive keys from it, then drop it. */
  plaintext: Bytes;
  /** Provider ciphertext, stored as `key.wrapped`. */
  wrapped: Uint8Array;
  /** Canonical key reference to store as `key.keyId` (for KMS, the ARN). */
  keyId: string;
}

/**
 * Wraps and unwraps bundle data keys. The key that does the wrapping must
 * live outside the platform that runs your app; that is the whole point.
 */
export interface KeyProvider {
  /** Stored as `key.provider`, e.g. "aws-kms". */
  readonly name: string;
  generateDataKey(keyId: string, ctx: KeyContext): Promise<GeneratedDataKey>;
  decryptDataKey(
    keyId: string,
    wrapped: Uint8Array,
    ctx: KeyContext
  ): Promise<Bytes>;
}

/** The context as a string map, the shape KMS encryption contexts take. */
export function keyContextMap(ctx: KeyContext): Record<string, string> {
  return {
    "keyseal:bundle": ctx.bundleId,
    "keyseal:env": ctx.env,
    "keyseal:epoch": String(ctx.epoch),
  };
}
