// Bundle types plus strict parse/serialize for format v1 (spec/FORMAT.md
// section 3). Parsing validates shape only; integrity is the MAC's job.

import { b64uDecode } from "./encoding.ts";
import { KeysealError } from "./errors.ts";

export const FORMAT_VERSION = 1;
export const MAX_VALUE_BYTES = 65536;

export interface PreviousValue {
  v: number;
  expiresAt: string;
  value: string;
}

export interface SecretEntry {
  v: number;
  rotatedAt: string;
  value: string;
  previous?: PreviousValue;
}

export interface BundleKeyRef {
  provider: string;
  keyId: string;
  /** Data key generation: 1 at creation, +1 on every rekey. */
  epoch: number;
  wrapped: string;
}

/** A parsed bundle. `secrets` is a Map so names like `__proto__` are safe. */
export interface Bundle {
  id: string;
  env: string;
  version: number;
  updatedAt: string;
  key: BundleKeyRef;
  secrets: Map<string, SecretEntry>;
  mac: string;
}

export const NAME_RE: RegExp = /^[A-Za-z_][A-Za-z0-9_]{0,254}$/;
export const ENV_RE: RegExp = /^[a-z0-9][a-z0-9-]{0,62}$/;
const PROVIDER_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const KEY_ID_RE = /^[\x20-\x7e]{1,2048}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export function isValidName(name: string): boolean {
  return NAME_RE.test(name);
}

export function isValidEnv(env: string): boolean {
  return ENV_RE.test(env);
}

function fail(message: string): never {
  throw new KeysealError("invalid_format", message);
}

type Obj = Record<string, unknown>;

function object(v: unknown, where: string): Obj {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    fail(`${where} must be an object`);
  }
  return v as Obj;
}

function onlyKeys(
  o: Obj,
  required: readonly string[],
  optional: readonly string[],
  where: string
): void {
  for (const k of required) {
    if (!Object.hasOwn(o, k)) fail(`${where} is missing "${k}"`);
  }
  for (const k of Object.keys(o)) {
    if (!required.includes(k) && !optional.includes(k)) {
      fail(`${where} has unknown field "${k}"`);
    }
  }
}

function int(v: unknown, min: number, where: string): number {
  if (
    typeof v !== "number" ||
    !Number.isSafeInteger(v) ||
    v < min ||
    Object.is(v, -0)
  ) {
    fail(`${where} must be an integer >= ${min}`);
  }
  return v;
}

function str(v: unknown, re: RegExp, where: string): string {
  if (typeof v !== "string" || !re.test(v)) fail(`${where} is not valid`);
  return v;
}

function time(v: unknown, where: string): string {
  const s = str(v, TIME_RE, where);
  if (Number.isNaN(Date.parse(s))) fail(`${where} is not a valid time`);
  return s;
}

function b64u(v: unknown, where: string): string {
  if (typeof v !== "string" || v.length === 0 || b64uDecode(v) === null) {
    fail(`${where} must be unpadded base64url`);
  }
  return v;
}

function ciphertext(v: unknown, where: string): string {
  const s = b64u(v, where);
  // nonce (12) + tag (16) at minimum, plaintext capped at MAX_VALUE_BYTES.
  const len = b64uDecode(s)?.length ?? 0;
  if (len < 28 || len > 28 + MAX_VALUE_BYTES) {
    fail(`${where} has an invalid length`);
  }
  return s;
}

/** Parse and validate bundle text. Throws KeysealError on any problem. */
export function parseBundle(text: string): Bundle {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    fail("bundle is not valid JSON");
  }
  const o = object(raw, "bundle");
  if (o.keyseal !== FORMAT_VERSION) {
    if (Object.hasOwn(o, "keyseal")) {
      throw new KeysealError(
        "unsupported_format",
        `bundle format ${JSON.stringify(o.keyseal)} is not supported (this library reads format ${FORMAT_VERSION})`
      );
    }
    fail('bundle is missing "keyseal"');
  }
  onlyKeys(
    o,
    ["keyseal", "id", "env", "version", "updatedAt", "key", "secrets", "mac"],
    [],
    "bundle"
  );

  const id = b64u(o.id, "id");
  if (id.length !== 22) fail("id must encode 16 bytes");

  const k = object(o.key, "key");
  onlyKeys(k, ["provider", "keyId", "epoch", "wrapped"], [], "key");

  const secrets = new Map<string, SecretEntry>();
  const rawSecrets = object(o.secrets, "secrets");
  for (const name of Object.keys(rawSecrets)) {
    if (!isValidName(name)) fail(`secret name "${name}" is not valid`);
    const where = `secrets.${name}`;
    const e = object(rawSecrets[name], where);
    onlyKeys(e, ["v", "rotatedAt", "value"], ["previous"], where);
    const entry: SecretEntry = {
      v: int(e.v, 1, `${where}.v`),
      rotatedAt: time(e.rotatedAt, `${where}.rotatedAt`),
      value: ciphertext(e.value, `${where}.value`),
    };
    if (Object.hasOwn(e, "previous")) {
      const p = object(e.previous, `${where}.previous`);
      onlyKeys(p, ["v", "expiresAt", "value"], [], `${where}.previous`);
      const pv = int(p.v, 1, `${where}.previous.v`);
      if (pv >= entry.v) fail(`${where}.previous.v must be less than v`);
      entry.previous = {
        v: pv,
        expiresAt: time(p.expiresAt, `${where}.previous.expiresAt`),
        value: ciphertext(p.value, `${where}.previous.value`),
      };
    }
    secrets.set(name, entry);
  }

  return {
    id,
    env: str(o.env, ENV_RE, "env"),
    version: int(o.version, 1, "version"),
    updatedAt: time(o.updatedAt, "updatedAt"),
    key: {
      provider: str(k.provider, PROVIDER_RE, "key.provider"),
      keyId: str(k.keyId, KEY_ID_RE, "key.keyId"),
      epoch: int(k.epoch, 1, "key.epoch"),
      wrapped: b64u(k.wrapped, "key.wrapped"),
    },
    secrets,
    mac: b64u(o.mac, "mac"),
  };
}

/** Names in spec order: ascending UTF-8 byte order (names are ASCII). */
export function sortedNames(secrets: Map<string, unknown>): string[] {
  return [...secrets.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * Serialize with the canonical field order, sorted secrets, 2-space indent
 * and a trailing newline, so every implementation writes identical files.
 */
export function serializeBundle(b: Bundle): string {
  // Null-prototype object: a secret named __proto__ stays a plain key.
  const secrets: Record<string, unknown> = Object.create(null);
  for (const name of sortedNames(b.secrets)) {
    const e = b.secrets.get(name) as SecretEntry;
    secrets[name] = {
      v: e.v,
      rotatedAt: e.rotatedAt,
      value: e.value,
      ...(e.previous
        ? {
            previous: {
              v: e.previous.v,
              expiresAt: e.previous.expiresAt,
              value: e.previous.value,
            },
          }
        : {}),
    };
  }
  const out = {
    keyseal: FORMAT_VERSION,
    id: b.id,
    env: b.env,
    version: b.version,
    updatedAt: b.updatedAt,
    key: {
      provider: b.key.provider,
      keyId: b.key.keyId,
      epoch: b.key.epoch,
      wrapped: b.key.wrapped,
    },
    secrets,
    mac: b.mac,
  };
  return `${JSON.stringify(out, null, 2)}\n`;
}
