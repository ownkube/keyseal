// Opening (spec section 7) and writing (section 8) bundles.

import {
  type BundleKeys,
  computeMac,
  decryptValue,
  deriveKeys,
  encryptValue,
  type Rng,
  secureRandom,
  valueAad,
  verifyMac,
} from "./crypto.ts";
import { b64uDecode, b64uEncode, formatTime } from "./encoding.ts";
import { KeysealError } from "./errors.ts";
import {
  type Bundle,
  isValidEnv,
  isValidName,
  parseBundle,
  type SecretEntry,
  serializeBundle,
  sortedNames,
} from "./format.ts";
import type { KeyContext, KeyProvider } from "./keys.ts";

export interface SecretValue {
  value: string;
  v: number;
  rotatedAt: string;
  /** Present only while the grace window is open. */
  previous?: { value: string; v: number; expiresAt: string };
}

export interface OpenedBundle {
  bundle: Bundle;
  secrets: Map<string, SecretValue>;
}

export interface OpenOptions {
  /** Refuse a bundle for any other environment. */
  env?: string;
  /** Refuse a bundle older than this version. */
  minVersion?: number;
  /** Clock override in epoch ms, for tests. */
  now?: number;
}

function contextOf(b: Bundle): KeyContext {
  return { bundleId: b.id, env: b.env, epoch: b.key.epoch };
}

/** Steps 2 to 4 of spec section 7, plus the minimum-version pin. */
export function checkBundle(
  b: Bundle,
  provider: KeyProvider,
  opts: OpenOptions = {}
): void {
  if (opts.env !== undefined && b.env !== opts.env) {
    throw new KeysealError(
      "env_mismatch",
      `bundle is for "${b.env}", expected "${opts.env}"`
    );
  }
  if (b.key.provider !== provider.name) {
    throw new KeysealError(
      "provider_mismatch",
      `bundle uses key provider "${b.key.provider}", but "${provider.name}" was supplied`
    );
  }
  if (opts.minVersion !== undefined && b.version < opts.minVersion) {
    throw new KeysealError(
      "rollback",
      `bundle version ${b.version} is older than the minimum ${opts.minVersion}`
    );
  }
}

/** Unwrap the data key through the provider and derive the bundle keys. */
export async function unlockBundle(
  b: Bundle,
  provider: KeyProvider
): Promise<BundleKeys> {
  const wrapped = b64uDecode(b.key.wrapped);
  if (wrapped === null) {
    throw new KeysealError("invalid_format", "key.wrapped is not base64url");
  }
  let dataKey: Uint8Array<ArrayBuffer>;
  try {
    dataKey = await provider.decryptDataKey(b.key.keyId, wrapped, contextOf(b));
  } catch (cause) {
    if (cause instanceof KeysealError) throw cause;
    throw new KeysealError(
      "key_unavailable",
      `could not unwrap the data key with ${provider.name} (${describe(cause)})`,
      { cause }
    );
  }
  try {
    return await deriveKeys(dataKey, b.id);
  } finally {
    dataKey.fill(0);
  }
}

function describe(err: unknown): string {
  if (err instanceof Error)
    return err.name === "Error" ? err.message : err.name;
  return String(err);
}

/** Verify the MAC, then decrypt every live value (section 7 steps 5-6). */
export async function readBundle(
  b: Bundle,
  keys: BundleKeys,
  now: number = Date.now()
): Promise<Map<string, SecretValue>> {
  await verifyMac(keys, b);
  const out = new Map<string, SecretValue>();
  for (const name of sortedNames(b.secrets)) {
    const e = b.secrets.get(name) as SecretEntry;
    const s: SecretValue = {
      value: await decryptValue(
        keys,
        valueAad(b.id, b.env, name, e.v, "current"),
        e.value,
        `secrets.${name}`
      ),
      v: e.v,
      rotatedAt: e.rotatedAt,
    };
    if (e.previous && Date.parse(e.previous.expiresAt) > now) {
      s.previous = {
        value: await decryptValue(
          keys,
          valueAad(b.id, b.env, name, e.previous.v, "previous"),
          e.previous.value,
          `secrets.${name}.previous`
        ),
        v: e.previous.v,
        expiresAt: e.previous.expiresAt,
      };
    }
    out.set(name, s);
  }
  return out;
}

/** Parse, check, unlock, verify and decrypt a bundle in one call. */
export async function openBundle(
  input: string | Bundle,
  provider: KeyProvider,
  opts: OpenOptions = {}
): Promise<OpenedBundle> {
  const bundle = typeof input === "string" ? parseBundle(input) : input;
  checkBundle(bundle, provider, opts);
  const keys = await unlockBundle(bundle, provider);
  return { bundle, secrets: await readBundle(bundle, keys, opts.now) };
}

export interface EditorOptions {
  /** Clock override returning epoch ms, for tests and test vectors. */
  now?: () => number;
  /** Randomness override, for reproducible test vectors only. */
  rng?: Rng;
}

export interface CreateOptions extends EditorOptions {
  env: string;
  keyId: string;
  provider: KeyProvider;
}

export interface SetOptions {
  /** Keep the replaced value readable as `previous` for this many ms. */
  grace?: number;
}

interface Plain {
  value: string;
  previous?: string;
}

/**
 * An unlocked bundle you can change and write back. Unchanged secrets keep
 * their exact ciphertext, so a git diff shows only what you touched.
 */
export class BundleEditor {
  #bundle: Bundle;
  #plain: Map<string, Plain>;
  #keys: BundleKeys;
  #provider: KeyProvider;
  #baseVersion: number;
  #now: () => number;
  #rng: Rng;
  #dirty = false;

  private constructor(
    bundle: Bundle,
    plain: Map<string, Plain>,
    keys: BundleKeys,
    provider: KeyProvider,
    baseVersion: number,
    opts: EditorOptions
  ) {
    this.#bundle = bundle;
    this.#plain = plain;
    this.#keys = keys;
    this.#provider = provider;
    this.#baseVersion = baseVersion;
    this.#now = opts.now ?? Date.now;
    this.#rng = opts.rng ?? secureRandom;
  }

  /** Start a new, empty bundle sealed under `keyId`. */
  static async create(opts: CreateOptions): Promise<BundleEditor> {
    if (!isValidEnv(opts.env)) {
      throw new KeysealError(
        "invalid_argument",
        `environment "${opts.env}" must be lowercase letters, digits and dashes`
      );
    }
    const rng = opts.rng ?? secureRandom;
    const now = opts.now ?? Date.now;
    const id = b64uEncode(rng(16));
    const generated = await generate(opts.provider, opts.keyId, {
      bundleId: id,
      env: opts.env,
      epoch: 1,
    });
    const bundle: Bundle = {
      id,
      env: opts.env,
      version: 0,
      updatedAt: formatTime(now()),
      key: {
        provider: opts.provider.name,
        keyId: generated.keyId,
        epoch: 1,
        wrapped: generated.wrapped,
      },
      secrets: new Map(),
      mac: "",
    };
    const editor = new BundleEditor(
      bundle,
      new Map(),
      generated.keys,
      opts.provider,
      0,
      opts
    );
    editor.#dirty = true;
    return editor;
  }

  /** Open existing bundle text for editing. Verifies it fully first. */
  static async open(
    text: string,
    provider: KeyProvider,
    opts: EditorOptions & { env?: string } = {}
  ): Promise<BundleEditor> {
    const now = opts.now ?? Date.now;
    const bundle = parseBundle(text);
    checkBundle(bundle, provider, opts.env ? { env: opts.env } : {});
    const keys = await unlockBundle(bundle, provider);
    const values = await readBundle(bundle, keys, now());
    const plain = new Map<string, Plain>();
    for (const [name, s] of values) {
      plain.set(name, {
        value: s.value,
        ...(s.previous ? { previous: s.previous.value } : {}),
      });
    }
    return new BundleEditor(
      bundle,
      plain,
      keys,
      provider,
      bundle.version,
      opts
    );
  }

  get id(): string {
    return this.#bundle.id;
  }

  get env(): string {
    return this.#bundle.env;
  }

  get provider(): string {
    return this.#bundle.key.provider;
  }

  get keyId(): string {
    return this.#bundle.key.keyId;
  }

  get epoch(): number {
    return this.#bundle.key.epoch;
  }

  /** Version of the bundle as opened (0 for a new one). */
  get version(): number {
    return this.#baseVersion;
  }

  get dirty(): boolean {
    return this.#dirty;
  }

  names(): string[] {
    return sortedNames(this.#bundle.secrets);
  }

  has(name: string): boolean {
    return this.#plain.has(name);
  }

  get(name: string): string | undefined {
    return this.#plain.get(name)?.value;
  }

  entry(name: string): SecretEntry | undefined {
    return this.#bundle.secrets.get(name);
  }

  /**
   * Set a secret. Returns false when the value is unchanged and nothing was
   * written. With `grace`, the old value stays readable as `previous`.
   */
  async set(
    name: string,
    value: string,
    opts: SetOptions = {}
  ): Promise<boolean> {
    if (!isValidName(name)) {
      throw new KeysealError(
        "invalid_argument",
        `"${name}" is not a valid secret name (letters, digits and _, not starting with a digit)`
      );
    }
    if (typeof value !== "string") {
      throw new KeysealError(
        "invalid_argument",
        "secret values must be strings"
      );
    }
    const grace = opts.grace ?? 0;
    if (!Number.isFinite(grace) || grace < 0) {
      throw new KeysealError("invalid_argument", "grace must be >= 0 ms");
    }
    const b = this.#bundle;
    const existing = b.secrets.get(name);
    const old = this.#plain.get(name);
    if (old && old.value === value && grace === 0) return false;

    const now = this.#now();
    const v = (existing?.v ?? 0) + 1;
    const entry: SecretEntry = {
      v,
      rotatedAt: formatTime(now),
      value: await this.#encrypt(name, v, "current", value),
    };
    const plain: Plain = { value };
    if (existing && old && grace > 0) {
      entry.previous = {
        v: existing.v,
        expiresAt: formatTime(now + grace),
        value: await this.#encrypt(name, existing.v, "previous", old.value),
      };
      plain.previous = old.value;
    }
    b.secrets.set(name, entry);
    this.#plain.set(name, plain);
    this.#dirty = true;
    return true;
  }

  /** Remove a secret. Returns false if it wasn't there. */
  remove(name: string): boolean {
    const had = this.#bundle.secrets.delete(name);
    this.#plain.delete(name);
    if (had) this.#dirty = true;
    return had;
  }

  /**
   * Seal everything under a fresh data key, optionally under a different
   * key, or a different provider (e.g. local to AWS KMS). Use it to move
   * keys, or if a data key may have been exposed.
   */
  async rekey(keyId?: string, provider?: KeyProvider): Promise<void> {
    if (provider && keyId === undefined) {
      throw new KeysealError(
        "invalid_argument",
        "moving to another provider needs a key id"
      );
    }
    const b = this.#bundle;
    // A new epoch puts the new data key under a new encryption context, so
    // an IAM Deny on the old epochs makes every older bundle undecryptable.
    const epoch = b.key.epoch + 1;
    const next = provider ?? this.#provider;
    const generated = await generate(next, keyId ?? b.key.keyId, {
      bundleId: b.id,
      env: b.env,
      epoch,
    });
    this.#keys = generated.keys;
    this.#provider = next;
    b.key = {
      provider: next.name,
      keyId: generated.keyId,
      epoch,
      wrapped: generated.wrapped,
    };
    const now = this.#now();
    for (const name of sortedNames(b.secrets)) {
      const e = b.secrets.get(name) as SecretEntry;
      const p = this.#plain.get(name) as Plain;
      e.value = await this.#encrypt(name, e.v, "current", p.value);
      if (
        e.previous &&
        p.previous !== undefined &&
        Date.parse(e.previous.expiresAt) > now
      ) {
        e.previous.value = await this.#encrypt(
          name,
          e.previous.v,
          "previous",
          p.previous
        );
      } else {
        delete e.previous;
      }
    }
    this.#dirty = true;
  }

  /** Produce the new bundle text: version + 1, fresh MAC, expired values dropped. */
  async seal(): Promise<string> {
    const b = this.#bundle;
    const now = this.#now();
    for (const e of b.secrets.values()) {
      if (e.previous && Date.parse(e.previous.expiresAt) <= now) {
        delete e.previous;
      }
    }
    b.version = this.#baseVersion + 1;
    b.updatedAt = formatTime(now);
    b.mac = await computeMac(this.#keys, b);
    return serializeBundle(b);
  }

  #encrypt(
    name: string,
    v: number,
    slot: "current" | "previous",
    value: string
  ): Promise<string> {
    const b = this.#bundle;
    return encryptValue(
      this.#keys,
      valueAad(b.id, b.env, name, v, slot),
      value,
      this.#rng
    );
  }

  toJSON(): { id: string; env: string; names: string[] } {
    return { id: this.id, env: this.env, names: this.names() };
  }
}

async function generate(
  provider: KeyProvider,
  keyId: string,
  ctx: KeyContext
): Promise<{ keys: BundleKeys; wrapped: string; keyId: string }> {
  let g: Awaited<ReturnType<KeyProvider["generateDataKey"]>>;
  try {
    g = await provider.generateDataKey(keyId, ctx);
  } catch (cause) {
    if (cause instanceof KeysealError) throw cause;
    throw new KeysealError(
      "key_unavailable",
      `could not create a data key with ${provider.name} (${describe(cause)})`,
      { cause }
    );
  }
  try {
    return {
      keys: await deriveKeys(g.plaintext, ctx.bundleId),
      wrapped: b64uEncode(g.wrapped),
      keyId: g.keyId,
    };
  } finally {
    g.plaintext.fill(0);
  }
}
