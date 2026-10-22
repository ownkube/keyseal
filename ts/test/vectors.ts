// Builds spec/testvectors/v1.json: the conformance suite every keyseal
// implementation must pass. Deterministic (seeded randomness, fixed clock),
// so regenerating produces a byte-identical file and CI can detect drift.

import { BundleEditor, openBundle } from "../src/bundle.ts";
import { computeMac, deriveKeys, type Rng } from "../src/crypto.ts";
import { b64uDecode, b64uEncode, type Bytes } from "../src/encoding.ts";
import { isKeysealError } from "../src/errors.ts";
import { type Bundle, parseBundle, serializeBundle } from "../src/format.ts";
import { type KeyProvider, keyContextMap } from "../src/keys.ts";
import { generateLocalKey, localKey, localKeyId } from "../src/local.ts";
import { testKeys } from "../src/testing.ts";

export interface ExpectedSecret {
  value: string;
  v: number;
  previous?: { value: string; v: number };
}

export type Outcome =
  | {
      ok: true;
      /** The context the reader must hand its key provider (section 4.1). */
      keyContext: Record<string, string>;
      secrets: Record<string, ExpectedSecret>;
    }
  | { ok: false; error: string };

/** An outcome before `vector` fills in the key context from the bundle. */
type Draft =
  | { ok: true; secrets: Record<string, ExpectedSecret> }
  | { ok: false; error: string };

export interface Vector {
  name: string;
  description: string;
  /** b64u data key the `test` provider hands back. */
  dataKey: string;
  /** Reader clock; decides whether `previous` values are still live. */
  now: string;
  /** If set, the reader pins this environment. */
  env?: string;
  /** Exact bundle file text. */
  bundle: string;
  expect: Outcome;
}

/** Unwrapping one data key with the `local` provider (spec section 4.3). */
export interface LocalVector {
  name: string;
  description: string;
  /** The local key the reader holds. */
  key: string;
  /** The bundle's `key.keyId`. */
  keyId: string;
  keyContext: Record<string, string>;
  /** The bundle's `key.wrapped`. */
  wrapped: string;
  expect:
    | {
        ok: true;
        /** What `key` derives as its id; equals `keyId`. */
        derivedKeyId: string;
        /** b64u of the unwrapped data key. */
        dataKey: string;
      }
    | { ok: false; error: string };
}

export interface VectorFile {
  format: 1;
  description: string;
  vectors: Vector[];
  localDescription: string;
  local: LocalVector[];
}

/** mulberry32: NOT for real keys, only to make fixtures reproducible. */
function seededRng(seed: number): Rng {
  let s = seed >>> 0;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      s = (s + 0x6d2b79f5) >>> 0;
      let t = s;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      out[i] = (t ^ (t >>> 14)) & 0xff;
    }
    return out;
  };
}

/** A plain-data object where "__proto__" is an ordinary own key. */
export function dict<T>(entries: [string, T][]): Record<string, T> {
  const out: Record<string, T> = Object.create(null);
  for (const [k, v] of entries) {
    Object.defineProperty(out, k, {
      value: v,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/** Key-sorted JSON, for comparing results without object-identity quirks. */
export function canon(x: unknown): string {
  if (x === null || typeof x !== "object") return JSON.stringify(x);
  if (Array.isArray(x)) return `[${x.map(canon).join(",")}]`;
  const o = x as Record<string, unknown>;
  const body = Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canon(o[k])}`)
    .join(",");
  return `{${body}}`;
}

const T0 = Date.parse("2026-10-22T12:00:00Z");
const HOUR = 3_600_000;
const iso = (ms: number): string =>
  new Date(ms).toISOString().replace(".000Z", "Z");

const DATA_KEY: Bytes = Uint8Array.from({ length: 32 }, (_, i) => i);
const OTHER_KEY: Bytes = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
const OLD_OPENAI = "sk-test-0000000000000000";
const NEW_OPENAI = "sk-test-1111111111111111";

const BASIC: [string, string][] = [
  ["DATABASE_URL", "postgres://app:s3cr3t@db.internal:5432/app"],
  ["OPENAI_API_KEY", OLD_OPENAI],
  ["EMPTY", ""],
  ["UNICODE", "pässwörd 🔑 秘密"],
  [
    "MULTILINE",
    "-----BEGIN KEY-----\nMIIBOgIBAAJBAKj34GkxFhD9\n-----END KEY-----\n",
  ],
];

type Json = Record<string, unknown>;

function edit(text: string, fn: (o: Json) => void): string {
  const o = JSON.parse(text) as Json;
  fn(o);
  return `${JSON.stringify(o, null, 2)}\n`;
}

function secretOf(o: Json, name: string): Json {
  return (o.secrets as Record<string, Json>)[name] as Json;
}

/** Modify a parsed bundle, then re-MAC it with the real key. */
async function remac(text: string, fn: (b: Bundle) => void): Promise<string> {
  const b = parseBundle(text);
  fn(b);
  b.mac = await computeMac(await deriveKeys(DATA_KEY, b.id), b);
  return serializeBundle(b);
}

function flipChar(s: string, at: number): string {
  return s.slice(0, at) + (s[at] === "A" ? "B" : "A") + s.slice(at + 1);
}

const ok = (entries: [string, ExpectedSecret][]): Draft => ({
  ok: true,
  secrets: dict(entries),
});
const err = (error: string): { ok: false; error: string } => ({
  ok: false,
  error,
});

function contextOf(text: string): Record<string, string> {
  const b = parseBundle(text);
  return keyContextMap({ bundleId: b.id, env: b.env, epoch: b.key.epoch });
}

export async function buildVectors(): Promise<VectorFile> {
  const provider = testKeys(DATA_KEY);
  let clock = T0;
  const opts = { now: () => clock, rng: seededRng(20261021) };
  const create = (env: string): Promise<BundleEditor> =>
    BundleEditor.create({ env, keyId: "test-key", provider, ...opts });

  const emptyText = await (await create("production")).seal();

  const basic = await create("production");
  for (const [k, v] of BASIC) await basic.set(k, v);
  const basicText = await basic.seal();

  clock = T0 + HOUR;
  const rotated = await BundleEditor.open(basicText, provider, opts);
  await rotated.set("OPENAI_API_KEY", NEW_OPENAI, { grace: 24 * HOUR });
  const rotatedText = await rotated.seal();

  const proto = await create("staging");
  await proto.set("__proto__", "not a prototype");
  await proto.set("constructor", "not a constructor");
  await proto.set("toString", "not a function");
  const protoText = await proto.seal();

  const rekeyed = await BundleEditor.open(basicText, provider, opts);
  await rekeyed.rekey();
  const rekeyedText = await rekeyed.seal();

  const basicExpect: [string, ExpectedSecret][] = BASIC.map(([k, v]) => [
    k,
    { value: v, v: 1 },
  ]);
  const withOpenai = (s: ExpectedSecret): [string, ExpectedSecret][] =>
    basicExpect.map(([k, e]) => [k, k === "OPENAI_API_KEY" ? s : e]);

  const dk = b64uEncode(DATA_KEY);
  const readAt = iso(T0 + 2 * HOUR);
  const vector = (
    name: string,
    description: string,
    bundle: string,
    expect: Draft,
    extra: Partial<Vector> = {}
  ): Vector => ({
    name,
    description,
    dataKey: dk,
    now: readAt,
    ...extra,
    bundle,
    expect: expect.ok
      ? { ok: true, keyContext: contextOf(bundle), secrets: expect.secrets }
      : expect,
  });

  const base = rotatedText;
  const openaiValue = secretOf(JSON.parse(base) as Json, "OPENAI_API_KEY")
    .value as string;

  const vectors: Vector[] = [
    vector("empty", "A bundle with no secrets.", emptyText, ok([])),
    vector(
      "basic",
      "Several secrets, including an empty, a non-ASCII and a multi-line value.",
      basicText,
      ok(basicExpect),
      { env: "production" }
    ),
    vector(
      "previous-live",
      "A rotated secret whose previous value is inside its grace window.",
      rotatedText,
      ok(
        withOpenai({
          value: NEW_OPENAI,
          v: 2,
          previous: { value: OLD_OPENAI, v: 1 },
        })
      )
    ),
    vector(
      "previous-expired",
      "The same bundle read after the grace window: previous must not be returned.",
      rotatedText,
      ok(withOpenai({ value: NEW_OPENAI, v: 2 })),
      { now: iso(T0 + 26 * HOUR) }
    ),
    vector(
      "prototype-names",
      "Names that collide with object internals in some languages.",
      protoText,
      ok([
        ["__proto__", { value: "not a prototype", v: 1 }],
        ["constructor", { value: "not a constructor", v: 1 }],
        ["toString", { value: "not a function", v: 1 }],
      ])
    ),
    vector(
      "rekeyed",
      "A rekeyed bundle: epoch 2, which the reader must pass to its key provider.",
      rekeyedText,
      ok(basicExpect)
    ),

    vector(
      "tampered-value",
      "One ciphertext character changed.",
      edit(base, (o) => {
        secretOf(o, "OPENAI_API_KEY").value = flipChar(openaiValue, 20);
      }),
      err("mac_mismatch")
    ),
    vector(
      "version-changed",
      "Bundle version edited.",
      edit(base, (o) => {
        o.version = (o.version as number) + 1;
      }),
      err("mac_mismatch")
    ),
    vector(
      "secret-removed",
      "A secret deleted from the file.",
      edit(base, (o) => {
        delete (o.secrets as Json).EMPTY;
      }),
      err("mac_mismatch")
    ),
    vector(
      "epoch-changed",
      "Key epoch edited, as if to dodge a revocation of the bundle's real epoch.",
      edit(base, (o) => {
        (o.key as Json).epoch = 7;
      }),
      err("mac_mismatch")
    ),
    vector(
      "previous-removed",
      "A grace-window previous value deleted.",
      edit(base, (o) => {
        delete secretOf(o, "OPENAI_API_KEY").previous;
      }),
      err("mac_mismatch")
    ),
    vector(
      "wrong-data-key",
      "An untouched bundle opened with a different data key.",
      base,
      err("mac_mismatch"),
      { dataKey: b64uEncode(OTHER_KEY) }
    ),
    vector(
      "swapped-values-valid-mac",
      "Two values swapped and the MAC recomputed: the AAD must bind each value to its name.",
      await remac(base, (b) => {
        const a = b.secrets.get("DATABASE_URL");
        const c = b.secrets.get("UNICODE");
        if (a && c) [a.value, c.value] = [c.value, a.value];
      }),
      err("decrypt_failed")
    ),
    vector(
      "slot-swap-valid-mac",
      "Current and previous ciphertexts swapped and the MAC recomputed.",
      await remac(base, (b) => {
        const e = b.secrets.get("OPENAI_API_KEY");
        if (e?.previous) {
          [e.value, e.previous.value] = [e.previous.value, e.value];
        }
      }),
      err("decrypt_failed")
    ),
    vector(
      "env-renamed-valid-mac",
      "Environment renamed and the MAC recomputed: the AAD must bind values to the environment.",
      await remac(base, (b) => {
        b.env = "staging";
      }),
      err("decrypt_failed")
    ),
    vector(
      "unknown-field",
      "An extra top-level field.",
      edit(base, (o) => {
        o.note = "hello";
      }),
      err("invalid_format")
    ),
    vector(
      "future-format",
      "A format version this reader doesn't know.",
      edit(base, (o) => {
        o.keyseal = 2;
      }),
      err("unsupported_format")
    ),
    vector(
      "padded-mac",
      "Base64 padding on the MAC.",
      edit(base, (o) => {
        o.mac = `${o.mac as string}=`;
      }),
      err("invalid_format")
    ),
    vector(
      "bad-name",
      "A secret name starting with a digit.",
      edit(base, (o) => {
        const s = o.secrets as Json;
        s["1BAD"] = s.EMPTY;
        delete s.EMPTY;
      }),
      err("invalid_format")
    ),
    vector(
      "previous-not-older",
      "previous.v equal to v.",
      edit(base, (o) => {
        const e = secretOf(o, "OPENAI_API_KEY");
        (e.previous as Json).v = e.v;
      }),
      err("invalid_format")
    ),
    vector(
      "fractional-timestamp",
      "Milliseconds in a timestamp.",
      edit(base, (o) => {
        o.updatedAt = (o.updatedAt as string).replace("Z", ".000Z");
      }),
      err("invalid_format")
    ),
    vector(
      "version-zero",
      "A version below 1.",
      edit(base, (o) => {
        o.version = 0;
      }),
      err("invalid_format")
    ),
    vector(
      "epoch-missing",
      "A key reference without an epoch.",
      edit(base, (o) => {
        delete (o.key as Json).epoch;
      }),
      err("invalid_format")
    ),
    vector(
      "epoch-zero",
      "A key epoch below 1.",
      edit(base, (o) => {
        (o.key as Json).epoch = 0;
      }),
      err("invalid_format")
    ),
    vector(
      "env-pinned-mismatch",
      "A valid bundle, but the reader pins another environment.",
      base,
      err("env_mismatch"),
      { env: "staging" }
    ),
    vector(
      "other-provider",
      "The bundle names a key provider the reader didn't supply.",
      edit(base, (o) => {
        (o.key as Json).provider = "aws-kms";
      }),
      err("provider_mismatch")
    ),
  ];

  return {
    format: 1,
    description:
      "keyseal format v1 conformance vectors. Open each bundle with the reserved `test` provider returning `dataKey`, the clock set to `now`, and the environment pinned to `env` when present. `ok` vectors must ask the provider for the data key with exactly `keyContext` and yield exactly `secrets` (with a previous value only where listed); the others must fail with `error`.",
    vectors,
    localDescription:
      "The `local` provider (section 4.3). Holding only `key`, unwrap `wrapped` for `keyId` with `keyContext`. `ok` vectors must derive `derivedKeyId` from `key` and return `dataKey`; the others must fail with `error`.",
    local: await buildLocalVectors(parseBundle(basicText).id),
  };
}

async function buildLocalVectors(bundleId: string): Promise<LocalVector[]> {
  const key = generateLocalKey(seededRng(43));
  const otherKey = generateLocalKey(seededRng(44));
  const keyId = await localKeyId(key);
  const ctx = { bundleId, env: "production", epoch: 2 };
  const g = await localKey({
    keys: key,
    rng: seededRng(45),
  }).generateDataKey(keyId, ctx);
  const wrapped = b64uEncode(g.wrapped);
  const base = { key, keyId, keyContext: keyContextMap(ctx), wrapped };
  const fails = (
    name: string,
    description: string,
    change: Partial<LocalVector>
  ): LocalVector => ({
    name,
    description,
    ...base,
    ...change,
    expect: err("key_unavailable"),
  });
  const withCtx = (change: Record<string, string>): Partial<LocalVector> => ({
    keyContext: { ...base.keyContext, ...change },
  });

  return [
    {
      name: "local-unwrap",
      description: "A data key wrapped with a local key, at epoch 2.",
      ...base,
      expect: {
        ok: true,
        derivedKeyId: keyId,
        dataKey: b64uEncode(g.plaintext),
      },
    },
    fails(
      "local-epoch-changed",
      "The same wrapped key presented under another epoch.",
      withCtx({ "keyseal:epoch": "3" })
    ),
    fails(
      "local-env-changed",
      "The same wrapped key presented for another environment.",
      withCtx({ "keyseal:env": "staging" })
    ),
    fails(
      "local-bundle-changed",
      "The same wrapped key copied into another bundle.",
      withCtx({ "keyseal:bundle": "AAAAAAAAAAAAAAAAAAAAAA" })
    ),
    fails("local-tampered", "One byte of the wrapped key changed.", {
      wrapped: flipChar(wrapped, 30),
    }),
    fails("local-truncated", "A wrapped key one byte short.", {
      wrapped: b64uEncode(g.wrapped.slice(0, -1)),
    }),
    fails(
      "local-other-key",
      "The reader holds a different local key than the bundle names.",
      { key: otherKey }
    ),
  ];
}

/** Run one local vector through this implementation. */
export async function runLocalVector(
  v: LocalVector
): Promise<LocalVector["expect"]> {
  const wrapped = b64uDecode(v.wrapped);
  if (!wrapped) throw new Error(`vector ${v.name}: bad wrapped`);
  const c = v.keyContext;
  try {
    const dk = await localKey({ keys: v.key }).decryptDataKey(
      v.keyId,
      wrapped,
      {
        bundleId: c["keyseal:bundle"] ?? "",
        env: c["keyseal:env"] ?? "",
        epoch: Number(c["keyseal:epoch"]),
      }
    );
    return {
      ok: true,
      derivedKeyId: await localKeyId(v.key),
      dataKey: b64uEncode(dk),
    };
  } catch (e) {
    if (isKeysealError(e)) return err(e.code);
    throw e;
  }
}

export function serializeVectors(file: VectorFile): string {
  return `${JSON.stringify(file, null, 2)}\n`;
}

/** Run one vector through this implementation. */
export async function runVector(v: Vector): Promise<Outcome> {
  const key = b64uDecode(v.dataKey);
  if (!key) throw new Error(`vector ${v.name}: bad dataKey`);
  const inner = testKeys(key);
  let keyContext: Record<string, string> = {};
  const provider: KeyProvider = {
    ...inner,
    decryptDataKey: (keyId, wrapped, ctx) => {
      keyContext = keyContextMap(ctx);
      return inner.decryptDataKey(keyId, wrapped, ctx);
    },
  };
  try {
    const { secrets } = await openBundle(v.bundle, provider, {
      now: Date.parse(v.now),
      ...(v.env !== undefined ? { env: v.env } : {}),
    });
    return {
      ok: true,
      keyContext,
      secrets: dict(
        [...secrets].map(([name, s]): [string, ExpectedSecret] => [
          name,
          {
            value: s.value,
            v: s.v,
            ...(s.previous
              ? { previous: { value: s.previous.value, v: s.previous.v } }
              : {}),
          },
        ])
      ),
    };
  } catch (e) {
    if (isKeysealError(e)) return err(e.code);
    throw e;
  }
}
