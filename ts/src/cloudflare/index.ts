// A keyseal Worker for Cloudflare (spec section 4.4). Holds the wrapping
// keys as a Worker secret, unwraps data keys for the apps KEYSEAL_ACCESS
// allows, and writes one log line per request to Workers Logs.
//
//   export { default } from "@ownkube/keyseal/cloudflare";
//
// Runs on the Workers free plan: one request per app start, and each one
// is a few WebCrypto calls.

import {
  b64uDecode,
  b64uEncode,
  type Bytes,
  bytesEqual,
  utf8,
} from "../encoding.ts";
import { isKeysealError } from "../errors.ts";
import { isValidEnv } from "../format.ts";
import type { KeyContext, KeyProvider } from "../keys.ts";
import { localKey, localKeyId } from "../local.ts";
import { CURRENT_WORKER_KEY } from "../worker.ts";
import {
  type Access,
  BUNDLE_ID_RE,
  type Client,
  ConfigError,
  ipAllowed,
  parseAccess,
  parseIp,
} from "./access.ts";
import {
  AuthError,
  JwksCache,
  looksLikeJwt,
  peekIssuer,
  verifyJwt,
} from "./oidc.ts";

export interface KeysealWorkerEnv {
  /** Wrapping keys, newest first; a Worker secret. */
  KEYSEAL_KEY?: string;
  /** Access rules, as JSON text or an object; a plain var. */
  KEYSEAL_ACCESS?: unknown;
}

export interface WorkerHandlerOptions {
  /** For OIDC discovery. Defaults to the global fetch. */
  fetch?: typeof globalThis.fetch;
  now?: () => number;
  /** Receives one audit record per request. Defaults to console.log. */
  log?: (record: Record<string, unknown>) => void;
}

export interface KeysealWorker {
  fetch(request: Request, env: KeysealWorkerEnv): Promise<Response>;
}

const KEY_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const WRAPPED_BYTES = 60;
const MAX_BODY = 4096;

interface Keys {
  provider: KeyProvider;
  /** Ids of KEYSEAL_KEY's keys; the first is the one new bundles use. */
  ids: Promise<string[]>;
}

type Op = "generate" | "decrypt";

class Refusal extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function reply(status: number, body: object): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

interface Parsed {
  keyId: string;
  ctx: KeyContext;
  wrapped?: Uint8Array;
}

function parseBody(op: Op, v: unknown): Parsed {
  const bad = (what: string): never => {
    throw new Refusal(400, `${what} is missing or not valid`);
  };
  if (typeof v !== "object" || v === null) return bad("the body");
  const o = v as Record<string, unknown>;
  const c = o.context as Record<string, unknown> | undefined;
  if (typeof c !== "object" || c === null) return bad("context");
  const { bundleId, env, epoch } = c;
  if (typeof bundleId !== "string" || !BUNDLE_ID_RE.test(bundleId))
    bad("context.bundleId");
  if (typeof env !== "string" || !isValidEnv(env)) bad("context.env");
  if (!Number.isSafeInteger(epoch) || (epoch as number) < 1)
    bad("context.epoch");
  const keyId = o.keyId;
  if (
    typeof keyId !== "string" ||
    !(
      KEY_ID_RE.test(keyId) ||
      (op === "generate" && keyId === CURRENT_WORKER_KEY)
    )
  )
    bad("keyId");
  const ctx = { bundleId, env, epoch } as KeyContext;
  if (op === "generate") return { keyId: keyId as string, ctx };
  const wrapped = typeof o.wrapped === "string" ? b64uDecode(o.wrapped) : null;
  if (wrapped?.length !== WRAPPED_BYTES) return bad("wrapped");
  return { keyId: keyId as string, ctx, wrapped };
}

/** Why `c` may not do `op` on this bundle, or null if it may. */
function denial(
  c: Client,
  op: Op,
  ctx: KeyContext,
  ip: Bytes | null
): string | null {
  if (op === "generate" && c.role !== "editor")
    return "an app may only decrypt";
  if (c.envs && !c.envs.includes(ctx.env))
    return `not allowed for environment ${ctx.env}`;
  if (c.bundles && !c.bundles.includes(ctx.bundleId))
    return `not allowed for bundle ${ctx.bundleId}`;
  if (c.ips && !ipAllowed(ip, c.ips)) return "not allowed from this address";
  return null;
}

/** Build a Worker. The default export is `createWorker()`. */
export function createWorker(opts: WorkerHandlerOptions = {}): KeysealWorker {
  const now = opts.now ?? Date.now;
  const log =
    opts.log ??
    ((r: Record<string, unknown>) => {
      // The audit trail: Workers Logs keeps it. Never holds keys or tokens.
      // oxlint-disable-next-line no-console
      console.log(JSON.stringify(r));
    });
  const jwks = new JwksCache({
    fetch: opts.fetch ?? ((...a) => globalThis.fetch(...a)),
    now,
  });

  // Parsed once per distinct config, not per request.
  let accessFor: { raw: unknown; access: Access } | undefined;
  let keysFor: ({ raw: string } & Keys) | undefined;

  function access(env: KeysealWorkerEnv): Access {
    if (accessFor && accessFor.raw === env.KEYSEAL_ACCESS)
      return accessFor.access;
    const parsed = parseAccess(env.KEYSEAL_ACCESS);
    accessFor = { raw: env.KEYSEAL_ACCESS, access: parsed };
    return parsed;
  }

  function keys(env: KeysealWorkerEnv): Keys {
    const raw = env.KEYSEAL_KEY ?? "";
    if (keysFor?.raw !== raw) {
      const specs = raw.split(/[\s,]+/).filter(Boolean);
      if (specs.length === 0) throw new ConfigError("KEYSEAL_KEY is not set");
      let provider: KeyProvider;
      try {
        provider = localKey({ keys: specs });
      } catch {
        // Never echo the secret, only that it is malformed.
        throw new ConfigError(
          'KEYSEAL_KEY holds something that is not a local key (make one with "keyseal key --new")'
        );
      }
      const ids = Promise.all(specs.map(localKeyId));
      keysFor = { raw, provider, ids };
    }
    return keysFor;
  }

  async function authenticate(
    token: string,
    a: Access,
    record: Record<string, unknown>
  ): Promise<Client[]> {
    if (looksLikeJwt(token)) {
      const iss = peekIssuer(token);
      const rules = a.clients.filter((c) => c.oidc?.issuer === iss);
      const matched: Client[] = [];
      const verified = new Map<string, Record<string, unknown>>();
      for (const c of rules) {
        const r = c.oidc;
        if (!r) continue;
        const key = `${r.issuer}\n${r.audience}`;
        let claims = verified.get(key);
        if (!claims) {
          try {
            claims = await verifyJwt(token, r.issuer, r.audience, jwks, now());
          } catch (e) {
            if (!(e instanceof AuthError)) throw e;
            record.auth = e.message;
            continue;
          }
          verified.set(key, claims);
        }
        if (
          (r.subject === undefined || claims.sub === r.subject) &&
          Object.entries(r.claims).every(([k, v]) => claims[k] === v)
        )
          matched.push(c);
      }
      return matched;
    }
    const hash = new Uint8Array(
      await globalThis.crypto.subtle.digest("SHA-256", utf8(token))
    );
    // Compare against every client, in constant time per comparison.
    return a.clients.filter(
      (c) => c.tokenHash !== undefined && bytesEqual(c.tokenHash, hash)
    );
  }

  async function handle(
    request: Request,
    env: KeysealWorkerEnv,
    record: Record<string, unknown>
  ): Promise<Response> {
    const path = new URL(request.url).pathname;
    const op: Op | null =
      path === "/v1/generate"
        ? "generate"
        : path === "/v1/decrypt"
          ? "decrypt"
          : null;
    if (!op) {
      if (request.method === "GET" && path === "/")
        return reply(200, { keyseal: "worker", version: 1 });
      throw new Refusal(404, "not found");
    }
    record.op = op;
    if (request.method !== "POST") throw new Refusal(405, "use POST");

    const a = access(env);
    const k = keys(env);

    const auth = request.headers.get("authorization") ?? "";
    const token = /^Bearer ([\x21-\x7e]{16,8192})$/.exec(auth)?.[1];
    if (!token) throw new Refusal(401, "missing bearer token");

    if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY)
      throw new Refusal(413, "body too large");
    const text = await request.text();
    if (text.length > MAX_BODY) throw new Refusal(413, "body too large");
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      throw new Refusal(400, "the body is not JSON");
    }
    const p = parseBody(op, body);
    Object.assign(record, {
      bundle: p.ctx.bundleId,
      env: p.ctx.env,
      epoch: p.ctx.epoch,
      keyId: p.keyId,
    });

    const clients = await authenticate(token, a, record);
    if (clients.length === 0) throw new Refusal(401, "unknown credentials");
    const ip = parseIp(request.headers.get("cf-connecting-ip") ?? "");
    const reasons: string[] = [];
    const allowed = clients.find((c) => {
      const why = denial(c, op, p.ctx, ip);
      if (why) reasons.push(`${c.name}: ${why}`);
      return why === null;
    });
    record.client = (allowed ?? clients[0])?.name;
    if (!allowed) throw new Refusal(403, reasons.join("; "));

    const min = a.minEpoch.get(p.ctx.bundleId);
    if (min !== undefined && p.ctx.epoch < min) {
      throw new Refusal(
        403,
        `epoch ${p.ctx.epoch} of this bundle is revoked; the oldest allowed is ${min}`
      );
    }

    const keyId =
      p.keyId === CURRENT_WORKER_KEY ? ((await k.ids)[0] ?? "") : p.keyId;
    record.keyId = keyId;
    try {
      if (op === "generate") {
        const g = await k.provider.generateDataKey(keyId, p.ctx);
        const res = reply(200, {
          keyId: g.keyId,
          plaintext: b64uEncode(g.plaintext),
          wrapped: b64uEncode(g.wrapped),
        });
        g.plaintext.fill(0);
        return res;
      }
      const dk = await k.provider.decryptDataKey(
        keyId,
        p.wrapped ?? new Uint8Array(0),
        p.ctx
      );
      const res = reply(200, { plaintext: b64uEncode(dk) });
      dk.fill(0);
      return res;
    } catch (e) {
      if (!isKeysealError(e, "key_unavailable")) throw e;
      if (!(await k.ids).includes(keyId))
        throw new Refusal(404, `this worker has no key ${keyId}`);
      throw new Refusal(
        422,
        "could not unwrap: the bundle's id, environment, epoch or wrapped key was changed"
      );
    }
  }

  return {
    async fetch(request, env) {
      const record: Record<string, unknown> = {
        keyseal: "request",
        at: new Date(now()).toISOString(),
        ip: request.headers.get("cf-connecting-ip") ?? undefined,
      };
      let res: Response;
      try {
        res = await handle(request, env, record);
      } catch (e) {
        if (e instanceof Refusal) {
          res = reply(e.status, { error: e.status, message: e.message });
          record.reason = e.message;
        } else if (e instanceof ConfigError) {
          // The config is the operator's; say what is wrong with it.
          res = reply(500, { error: 500, message: "worker misconfigured" });
          record.reason = `config: ${e.message}`;
        } else {
          res = reply(500, { error: 500, message: "internal error" });
          record.reason = e instanceof Error ? e.message : String(e);
        }
      }
      record.status = res.status;
      if (record.op) log(record);
      return res;
    },
  };
}

const worker: KeysealWorker = createWorker();
export default worker;
