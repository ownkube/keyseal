// The `worker` key provider (spec section 4.4): the wrapping key lives in a
// small HTTPS service you run, such as the Cloudflare Worker in
// `@ownkube/keyseal/cloudflare`, and the app asks it to unwrap the data key
// once at startup. The service checks who is asking, for which bundle,
// environment and epoch, and logs every request.

import { b64uDecode, b64uEncode, type Bytes } from "./encoding.ts";
import { KeysealError } from "./errors.ts";
import type { GeneratedDataKey, KeyContext, KeyProvider } from "./keys.ts";

/** Ask the service to wrap under whichever key it currently writes with. */
export const CURRENT_WORKER_KEY = "current";

const KEY_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const WRAPPED_BYTES = 60;

export interface WorkerKeyOptions {
  /** The service's base URL. Defaults to KEYSEAL_WORKER_URL. */
  url?: string;
  /**
   * A bearer token, or a function returning one (for example a platform
   * OIDC token, fetched fresh). Defaults to KEYSEAL_WORKER_TOKEN.
   */
  token?: string | (() => string | Promise<string>);
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout. Default 10 seconds. */
  timeoutMs?: number;
}

function envVar(name: string): string | undefined {
  const g = globalThis as {
    process?: { env?: Record<string, string | undefined> };
  };
  return g.process?.env?.[name] || undefined;
}

/** Parse and check a service URL. The bundle never chooses it. */
export function workerBaseUrl(href: string): URL {
  let u: URL;
  try {
    u = new URL(href);
  } catch {
    throw new KeysealError("invalid_argument", "the worker URL is not a URL");
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) {
    throw new KeysealError(
      "invalid_argument",
      `the worker URL must use https (got ${u.protocol})`
    );
  }
  if (u.username || u.password || u.search || u.hash) {
    throw new KeysealError(
      "invalid_argument",
      "the worker URL takes no credentials, query or fragment; pass the token separately"
    );
  }
  if (!u.pathname.endsWith("/")) u.pathname += "/";
  return u;
}

function decodeField(v: unknown, bytes: number, what: string): Bytes {
  const b = typeof v === "string" ? b64uDecode(v) : null;
  if (b?.length !== bytes) {
    throw new KeysealError(
      "key_unavailable",
      `the worker returned an invalid ${what}`
    );
  }
  return b;
}

/**
 * A key provider backed by a keyseal Worker. Sends the bundle's id,
 * environment and epoch with every call; the Worker decides whether this
 * caller may open that bundle.
 */
export function worker(opts: WorkerKeyOptions = {}): KeyProvider {
  const href = opts.url ?? envVar("KEYSEAL_WORKER_URL");
  if (!href) {
    throw new KeysealError(
      "invalid_argument",
      "no worker URL: pass url or set KEYSEAL_WORKER_URL"
    );
  }
  const base = workerBaseUrl(href);
  const where = `${base.origin}${base.pathname}`;
  const doFetch = opts.fetch ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 10_000;

  async function token(): Promise<string> {
    const t =
      typeof opts.token === "function"
        ? await opts.token()
        : (opts.token ?? envVar("KEYSEAL_WORKER_TOKEN"));
    if (!t) {
      throw new KeysealError(
        "key_unavailable",
        "no worker token: set KEYSEAL_WORKER_TOKEN"
      );
    }
    return t;
  }

  async function call(
    op: "generate" | "decrypt",
    body: object
  ): Promise<Record<string, unknown>> {
    const auth = await token();
    let res: Response;
    try {
      res = await doFetch(new URL(`v1/${op}`, base), {
        method: "POST",
        headers: {
          authorization: `Bearer ${auth}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
        // A redirect could carry the token somewhere else.
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (cause) {
      throw new KeysealError(
        "key_unavailable",
        `could not reach the worker at ${where}`,
        { cause }
      );
    }
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    const obj =
      json && typeof json === "object" ? (json as Record<string, unknown>) : {};
    if (!res.ok) {
      const why = typeof obj.message === "string" ? obj.message : "";
      throw new KeysealError(
        "key_unavailable",
        `the worker refused (HTTP ${res.status})${why ? `: ${why.slice(0, 300)}` : ""}`
      );
    }
    return obj;
  }

  return {
    name: "worker",

    async generateDataKey(
      keyId: string,
      ctx: KeyContext
    ): Promise<GeneratedDataKey> {
      const r = await call("generate", { keyId, context: ctx });
      if (typeof r.keyId !== "string" || !KEY_ID_RE.test(r.keyId)) {
        throw new KeysealError(
          "key_unavailable",
          "the worker returned an invalid key id"
        );
      }
      if (keyId !== CURRENT_WORKER_KEY && r.keyId !== keyId) {
        throw new KeysealError(
          "key_unavailable",
          "the worker wrapped under a different key than asked"
        );
      }
      const wrapped = decodeField(r.wrapped, WRAPPED_BYTES, "wrapped key");
      const plaintext = decodeField(r.plaintext, 32, "data key");
      return { plaintext, wrapped, keyId: r.keyId };
    },

    async decryptDataKey(
      keyId: string,
      wrapped: Uint8Array,
      ctx: KeyContext
    ): Promise<Bytes> {
      if (!KEY_ID_RE.test(keyId)) {
        throw new KeysealError(
          "key_unavailable",
          "key.keyId is not a worker key id"
        );
      }
      const r = await call("decrypt", {
        keyId,
        wrapped: b64uEncode(wrapped),
        context: ctx,
      });
      return decodeField(r.plaintext, 32, "data key");
    },
  };
}
