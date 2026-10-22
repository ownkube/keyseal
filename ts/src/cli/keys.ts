// Which key provider opens a bundle, and where the CLI keeps local keys:
// one file per key in ~/.config/keyseal/keys, readable only by you.
// Worker bundles need the Worker's URL and a token, from flags or env.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { awsKms } from "../aws.ts";
import { secureRandom } from "../crypto.ts";
import { b64uEncode, utf8 } from "../encoding.ts";
import { KeysealError } from "../errors.ts";
import type { Bundle } from "../format.ts";
import type { KeyProvider } from "../keys.ts";
import { generateLocalKey, localKey, localKeyId } from "../local.ts";
import { worker } from "../worker.ts";

const LOCAL_ID_RE = /^[A-Za-z0-9_-]{22}$/;

/** KEYSEAL_KEY_DIR, else $XDG_CONFIG_HOME/keyseal/keys, else ~/.config/... */
export function keyDir(): string {
  return (
    process.env.KEYSEAL_KEY_DIR ??
    join(
      process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"),
      "keyseal",
      "keys"
    )
  );
}

function keyPath(keyId: string): string {
  // keyId comes from the bundle; never let it pick a path.
  if (!LOCAL_ID_RE.test(keyId)) {
    throw new KeysealError("invalid_format", "key.keyId is not a local key id");
  }
  return join(keyDir(), `${keyId}.key`);
}

/** KEYSEAL_KEY, plus the saved key for `keyId` if there is one. */
async function localKeys(keyId: string): Promise<string[]> {
  const keys = (process.env.KEYSEAL_KEY ?? "").split(/[\s,]+/).filter(Boolean);
  try {
    keys.push((await readFile(keyPath(keyId), "utf8")).trim());
  } catch (err) {
    if (err instanceof KeysealError) throw err;
    // Not saved on this machine.
  }
  return keys;
}

export function awsKeys(region: string | undefined): KeyProvider {
  return awsKms(region ? { region } : {});
}

/**
 * A Worker provider. The URL comes from --worker or KEYSEAL_WORKER_URL,
 * never from the bundle, so a bundle can't send the token elsewhere.
 */
export function workerKeys(url: string | undefined): KeyProvider {
  const href = url ?? process.env.KEYSEAL_WORKER_URL;
  if (!href) {
    throw new KeysealError(
      "invalid_argument",
      "this bundle is sealed by a keyseal Worker: pass --worker <url> or set KEYSEAL_WORKER_URL"
    );
  }
  return worker({ url: href });
}

export interface ProviderOptions {
  region?: string | undefined;
  worker?: string | undefined;
}

/** The provider the bundle names, loaded with whatever keys it needs. */
export async function providerFor(
  b: Bundle,
  opts: ProviderOptions
): Promise<KeyProvider> {
  switch (b.key.provider) {
    case "aws-kms":
      return awsKeys(opts.region);
    case "local":
      return localKey({ keys: await localKeys(b.key.keyId) });
    case "worker":
      return workerKeys(opts.worker);
    default:
      throw new KeysealError(
        "provider_mismatch",
        `the bundle uses key provider "${b.key.provider}", which this CLI can't open`
      );
  }
}

export interface NewLocalKey {
  keyId: string;
  path: string;
  provider: KeyProvider;
}

/** Make a local key and save it with mode 0600. Never prints it. */
export async function newLocalKey(): Promise<NewLocalKey> {
  const key = generateLocalKey();
  const keyId = await localKeyId(key);
  await mkdir(keyDir(), { recursive: true, mode: 0o700 });
  const path = keyPath(keyId);
  await writeFile(path, `${key}\n`, { mode: 0o600, flag: "wx" });
  return { keyId, path, provider: localKey({ keys: [key] }) };
}

export interface WorkerToken {
  token: string;
  /** What goes in KEYSEAL_ACCESS: "sha256:" and the token's hash. */
  hash: string;
}

/** A new Worker bearer token and the hash the Worker's config stores. */
export async function newWorkerToken(): Promise<WorkerToken> {
  const token = `keyseal_wt_${b64uEncode(secureRandom(32))}`;
  const digest = await globalThis.crypto.subtle.digest("SHA-256", utf8(token));
  return { token, hash: `sha256:${b64uEncode(new Uint8Array(digest))}` };
}

/** The local key a bundle is sealed with, from KEYSEAL_KEY or the key dir. */
export async function findLocalKey(keyId: string): Promise<string> {
  for (const k of await localKeys(keyId)) {
    if ((await localKeyId(k)) === keyId) return k;
  }
  throw new KeysealError(
    "key_unavailable",
    `local key ${keyId} is not in KEYSEAL_KEY or ${keyDir()}`
  );
}
