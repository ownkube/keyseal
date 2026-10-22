// The runtime: load a bundle once, serve values from memory, poll for a new
// bundle, and tell the app when secrets rotate. Values stay out of
// process.env unless you opt in.

import {
  checkBundle,
  readBundle,
  type SecretValue,
  unlockBundle,
} from "./bundle.ts";
import type { BundleKeys } from "./crypto.ts";
import { KeysealError } from "./errors.ts";
import { type Bundle, parseBundle } from "./format.ts";
import type { KeyProvider } from "./keys.ts";
import { file, type Source, url } from "./sources.ts";

export interface KeysealOptions {
  /** A Source, a file path, or an https:// URL. For S3 use `s3()` from `@ownkube/keyseal/s3`. */
  source: Source | string;
  keys: KeyProvider;
  /** Refuse bundles for any other environment. Recommended. */
  env?: string;
  /** Refuse bundles older than this version, including on first load. */
  minVersion?: number;
  /** Poll interval in ms, or false. Defaults to 30s (off for inline bundles). */
  poll?: number | false;
  /** Also write values into process.env: every secret, or just these names. */
  inject?: boolean | readonly string[];
}

export interface RotatedEvent {
  version: number;
  /** Secrets whose value changed. */
  changed: string[];
  added: string[];
  removed: string[];
}

interface Events {
  rotated: (e: RotatedEvent) => void;
  error: (err: unknown) => void;
}

export interface Keyseal {
  /** The current value. Throws `not_found` for an unknown name. */
  get(name: string): string;
  has(name: string): boolean;
  /** The value replaced by the last rotation, while its grace window is open. */
  previous(name: string): string | undefined;
  names(): string[];
  /** Every current value, e.g. to hand to a child process. */
  toEnv(): Record<string, string>;
  /** Replace every known secret value in `text` with `[redacted:NAME]`. */
  redact(text: string): string;
  /** Check the source now. Resolves true if a new bundle was loaded. */
  refresh(): Promise<boolean>;
  on<E extends keyof Events>(event: E, fn: Events[E]): () => void;
  close(): void;
  readonly id: string;
  readonly env: string;
  readonly version: number;
  readonly updatedAt: string;
}

const DEFAULT_POLL_MS = 30_000;
const MIN_POLL_MS = 1_000;
// Shorter values would turn redaction into noise across ordinary text.
const MIN_REDACT_LENGTH = 8;

function toSource(s: Source | string): Source {
  if (typeof s !== "string") return s;
  if (s.startsWith("s3://")) {
    throw new KeysealError(
      "invalid_argument",
      'for S3, pass s3("s3://...") from "@ownkube/keyseal/s3"'
    );
  }
  return /^https?:\/\//.test(s) ? url(s) : file(s);
}

interface State {
  bundle: Bundle;
  secrets: Map<string, SecretValue>;
  keys: BundleKeys;
  keyRef: string;
  etag: string | undefined;
  redactions: [string, string][];
}

export async function createKeyseal(opts: KeysealOptions): Promise<Keyseal> {
  const source = toSource(opts.source);
  const provider = opts.keys;
  const listeners: { [E in keyof Events]: Set<Events[E]> } = {
    rotated: new Set(),
    error: new Set(),
  };
  const injected = new Set<string>();

  async function load(
    body: string,
    etag: string | undefined,
    current: State | undefined
  ): Promise<State | null> {
    const bundle = parseBundle(body);
    checkBundle(bundle, provider, {
      ...(opts.env !== undefined ? { env: opts.env } : {}),
      ...(opts.minVersion !== undefined ? { minVersion: opts.minVersion } : {}),
    });
    if (current) {
      if (bundle.id !== current.bundle.id) {
        throw new KeysealError(
          "bundle_changed",
          "the source now serves a different bundle; restart to accept it"
        );
      }
      if (
        bundle.version === current.bundle.version &&
        bundle.mac === current.bundle.mac
      ) {
        current.etag = etag;
        return null;
      }
      if (bundle.version <= current.bundle.version) {
        throw new KeysealError(
          "rollback",
          `refusing bundle version ${bundle.version}: version ${current.bundle.version} is already loaded`
        );
      }
    }
    const keyRef = `${bundle.key.keyId}\n${bundle.key.wrapped}`;
    const keys =
      current && current.keyRef === keyRef
        ? current.keys
        : await unlockBundle(bundle, provider);
    const secrets = await readBundle(bundle, keys);
    return {
      bundle,
      secrets,
      keys,
      keyRef,
      etag,
      redactions: redactionsOf(secrets),
    };
  }

  const first = await source.read();
  if (!first) {
    throw new KeysealError(
      "source_unavailable",
      `${source.description} returned nothing`
    );
  }
  let state = (await load(first.body, first.etag, undefined)) as State;
  applyInject(state, undefined);

  function applyInject(next: State, prev: State | undefined): void {
    const env = (
      globalThis as { process?: { env?: Record<string, string | undefined> } }
    ).process?.env;
    if (!opts.inject || !env) return;
    const wanted =
      opts.inject === true ? [...next.secrets.keys()] : opts.inject;
    for (const name of wanted) {
      const s = next.secrets.get(name);
      if (s) {
        env[name] = s.value;
        injected.add(name);
      }
    }
    if (prev) {
      for (const name of injected) {
        if (!next.secrets.has(name)) {
          delete env[name];
          injected.delete(name);
        }
      }
    }
  }

  function emit<E extends keyof Events>(
    event: E,
    arg: Parameters<Events[E]>[0]
  ): void {
    for (const fn of listeners[event]) {
      try {
        (fn as (a: typeof arg) => void)(arg);
      } catch (err) {
        if (event !== "error") emit("error", err);
      }
    }
  }

  let inflight: Promise<boolean> | null = null;
  async function doRefresh(): Promise<boolean> {
    const read = await source.read(state.etag);
    if (!read) return false;
    const next = await load(read.body, read.etag, state);
    if (!next) return false;
    const prev = state;
    state = next;
    applyInject(next, prev);
    emit("rotated", diff(prev, next));
    return true;
  }
  function refresh(): Promise<boolean> {
    inflight ??= doRefresh().finally(() => {
      inflight = null;
    });
    return inflight;
  }

  const requested =
    opts.poll === false
      ? 0
      : (opts.poll ?? (source.static ? 0 : DEFAULT_POLL_MS));
  const interval = requested > 0 ? Math.max(MIN_POLL_MS, requested) : 0;
  let timer: ReturnType<typeof setInterval> | undefined;
  if (interval > 0) {
    timer = setInterval(() => {
      refresh().catch((err) => emit("error", err));
    }, interval);
    // Polling must never keep a process alive on its own.
    (timer as { unref?: () => void }).unref?.();
  }

  const ks: Keyseal = {
    get(name) {
      const s = state.secrets.get(name);
      if (!s) {
        throw new KeysealError(
          "not_found",
          `secret "${name}" is not in the bundle`
        );
      }
      return s.value;
    },
    has(name) {
      return state.secrets.has(name);
    },
    previous(name) {
      const p = state.secrets.get(name)?.previous;
      return p && Date.parse(p.expiresAt) > Date.now() ? p.value : undefined;
    },
    names() {
      return [...state.secrets.keys()];
    },
    toEnv() {
      const out: Record<string, string> = Object.create(null);
      for (const [name, s] of state.secrets) out[name] = s.value;
      return out;
    },
    redact(text) {
      let out = text;
      for (const [value, name] of state.redactions) {
        if (out.includes(value))
          out = out.split(value).join(`[redacted:${name}]`);
      }
      return out;
    },
    refresh,
    on(event, fn) {
      listeners[event].add(fn);
      return () => {
        listeners[event].delete(fn);
      };
    },
    close() {
      if (timer) clearInterval(timer);
      listeners.rotated.clear();
      listeners.error.clear();
    },
    get id() {
      return state.bundle.id;
    },
    get env() {
      return state.bundle.env;
    },
    get version() {
      return state.bundle.version;
    },
    get updatedAt() {
      return state.bundle.updatedAt;
    },
  };
  // Logging the client must never print a value.
  Object.defineProperty(ks, "toJSON", {
    value: () => ({
      id: ks.id,
      env: ks.env,
      version: ks.version,
      names: ks.names(),
    }),
  });
  Object.defineProperty(ks, Symbol.for("nodejs.util.inspect.custom"), {
    value: () =>
      `Keyseal { env: ${ks.env}, version: ${ks.version}, secrets: ${state.secrets.size} }`,
  });
  return ks;
}

function redactionsOf(secrets: Map<string, SecretValue>): [string, string][] {
  const out: [string, string][] = [];
  for (const [name, s] of secrets) {
    if (s.value.length >= MIN_REDACT_LENGTH) out.push([s.value, name]);
    if (s.previous && s.previous.value.length >= MIN_REDACT_LENGTH) {
      out.push([s.previous.value, name]);
    }
  }
  // Longest first, so a value that contains another is replaced whole.
  return out.sort((a, b) => b[0].length - a[0].length);
}

function diff(prev: State, next: State): RotatedEvent {
  const changed: string[] = [];
  const added: string[] = [];
  const removed: string[] = [];
  for (const [name, s] of next.secrets) {
    const old = prev.secrets.get(name);
    if (!old) added.push(name);
    else if (old.v !== s.v) changed.push(name);
  }
  for (const name of prev.secrets.keys()) {
    if (!next.secrets.has(name)) removed.push(name);
  }
  return { version: next.bundle.version, changed, added, removed };
}
