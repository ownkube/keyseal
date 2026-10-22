// Helpers for testing apps that use keyseal, with no KMS and no network.
// `testKeys` is the reserved `test` key provider (spec section 9): it hands
// back a data key you supply. Never use any of this for real secrets: the
// "wrapped" key protects nothing.

import { BundleEditor } from "./bundle.ts";
import { type Bytes, bytesEqual, own, utf8 } from "./encoding.ts";
import { KeysealError } from "./errors.ts";
import type { GeneratedDataKey, KeyProvider } from "./keys.ts";
import type { Source } from "./sources.ts";

const WRAPPED = utf8("test");

/** A key provider for tests. Every call hands back `dataKey` (32 bytes). */
export function testKeys(
  dataKey: Uint8Array = new Uint8Array(32)
): KeyProvider {
  if (dataKey.length !== 32) {
    throw new KeysealError(
      "invalid_argument",
      "test data key must be 32 bytes"
    );
  }
  const key = own(dataKey);
  return {
    name: "test",
    async generateDataKey(keyId: string): Promise<GeneratedDataKey> {
      return { plaintext: own(key), wrapped: own(WRAPPED), keyId };
    },
    async decryptDataKey(_keyId: string, wrapped: Uint8Array): Promise<Bytes> {
      if (!bytesEqual(wrapped, WRAPPED)) {
        throw new KeysealError(
          "key_unavailable",
          "test provider only unwraps its fixed marker"
        );
      }
      return own(key);
    },
  };
}

export interface SealTestBundleOptions {
  /** Environment name. Defaults to "test". */
  env?: string;
  /** Defaults to `testKeys()`. Pass the same provider to `createKeyseal`. */
  keys?: KeyProvider;
}

/** Seal a bundle holding `secrets`, for tests. */
export async function sealTestBundle(
  secrets: Record<string, string>,
  opts: SealTestBundleOptions = {}
): Promise<string> {
  const editor = await BundleEditor.create({
    env: opts.env ?? "test",
    keyId: "test",
    provider: opts.keys ?? testKeys(),
  });
  for (const [name, value] of Object.entries(secrets)) {
    await editor.set(name, value);
  }
  return editor.seal();
}

export interface TestSource extends Source {
  /** The bundle text currently served. */
  readonly body: string;
  /** How many times the source has been read. */
  readonly reads: number;
  /** Serve a new bundle, as if it had just been uploaded. */
  publish(body: string): void;
}

/** A source you can update from a test to simulate a rotation. */
export function testSource(body: string): TestSource {
  let current = body;
  let generation = 0;
  let reads = 0;
  return {
    description: "test source",
    get body() {
      return current;
    },
    get reads() {
      return reads;
    },
    async read(etag) {
      reads++;
      const tag = String(generation);
      return etag === tag ? null : { body: current, etag: tag };
    },
    publish(next) {
      current = next;
      generation++;
    },
  };
}
