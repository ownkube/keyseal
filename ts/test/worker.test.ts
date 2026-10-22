import type { webcrypto } from "node:crypto";
import { describe, expect, it } from "vite-plus/test";
import { BundleEditor, openBundle } from "../src/bundle.ts";
import { workerAccess } from "../src/cli/policy.ts";
import {
  createWorker,
  type KeysealWorkerEnv,
  type WorkerHandlerOptions,
} from "../src/cloudflare/index.ts";
import { parseAccess } from "../src/cloudflare/access.ts";
import { b64uDecode, b64uEncode, utf8 } from "../src/encoding.ts";
import { isKeysealError } from "../src/errors.ts";
import { parseBundle } from "../src/format.ts";
import { generateLocalKey, localKeyId } from "../src/local.ts";
import { CURRENT_WORKER_KEY, worker } from "../src/worker.ts";

const subtle = globalThis.crypto.subtle;
const BASE = "https://keyseal.example.workers.dev/";

async function hashOf(token: string): Promise<string> {
  const d = await subtle.digest("SHA-256", utf8(token));
  return `sha256:${b64uEncode(new Uint8Array(d))}`;
}

function newToken(): string {
  return `keyseal_wt_${b64uEncode(globalThis.crypto.getRandomValues(new Uint8Array(32)))}`;
}

type Records = Record<string, unknown>[];

/** A Worker plus a client wired to it in-process. */
function setup(
  env: KeysealWorkerEnv,
  opts: WorkerHandlerOptions = {}
): {
  records: Records;
  client: (token: string, ip?: string) => ReturnType<typeof worker>;
  raw: (path: string, token: string, body: unknown) => Promise<Response>;
} {
  const records: Records = [];
  const w = createWorker({ log: (r) => records.push(r), ...opts });
  const send = (req: Request, ip?: string): Promise<Response> => {
    const headers = new Headers(req.headers);
    if (ip) headers.set("cf-connecting-ip", ip);
    return w.fetch(new Request(req, { headers }), env);
  };
  return {
    records,
    client: (token, ip) =>
      worker({
        url: BASE,
        token,
        fetch: (input, init) => send(new Request(input, init), ip),
      }),
    raw: (path, token, body) =>
      send(
        new Request(new URL(path, BASE), {
          method: "POST",
          headers: { authorization: `Bearer ${token}` },
          body: JSON.stringify(body),
        })
      ),
  };
}

async function errorOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    if (isKeysealError(e)) return `${e.code}: ${e.message}`;
    throw e;
  }
}

async function create(
  provider: ReturnType<typeof worker>,
  env = "production"
): Promise<string> {
  const ed = await BundleEditor.create({
    env,
    keyId: CURRENT_WORKER_KEY,
    provider,
  });
  await ed.set("STRIPE_SECRET_KEY", "sk_test_worker");
  return ed.seal();
}

/** A Worker with an editor and an app; returns a sealed bundle and its id. */
async function withBundle() {
  const key = generateLocalKey();
  const editorToken = newToken();
  const appToken = newToken();
  const editor = {
    name: "alice",
    role: "editor",
    token: await hashOf(editorToken),
  };
  const env: KeysealWorkerEnv = {
    KEYSEAL_KEY: key,
    KEYSEAL_ACCESS: JSON.stringify({ clients: [editor] }),
  };
  const w = setup(env);
  const text = await create(w.client(editorToken));
  const id = parseBundle(text).id;
  const app = {
    name: "prod-app",
    role: "app",
    env: "production",
    bundle: id,
    token: await hashOf(appToken),
  };
  env.KEYSEAL_ACCESS = JSON.stringify({ clients: [editor, app] });
  return { key, env, w, text, id, editorToken, appToken, editor, app };
}

describe("worker key provider", () => {
  it("seals through the Worker and opens with an app token", async () => {
    const t = await withBundle();
    const b = parseBundle(t.text);
    expect(b.key.provider).toBe("worker");
    expect(b.key.keyId).toBe(await localKeyId(t.key));
    const { secrets } = await openBundle(t.text, t.w.client(t.appToken));
    expect(secrets.get("STRIPE_SECRET_KEY")?.value).toBe("sk_test_worker");
  });

  it("logs every request without tokens or keys", async () => {
    const t = await withBundle();
    await openBundle(t.text, t.w.client(t.appToken));
    const last = t.w.records.at(-1);
    expect(last).toMatchObject({
      op: "decrypt",
      client: "prod-app",
      bundle: t.id,
      env: "production",
      epoch: 1,
      status: 200,
    });
    const all = JSON.stringify(t.w.records);
    expect(all).not.toContain(t.appToken);
    expect(all).not.toContain(t.editorToken);
    expect(all).not.toContain(t.key);
  });

  it("lets an app only decrypt", async () => {
    const t = await withBundle();
    expect(await errorOf(create(t.w.client(t.appToken)))).toMatch(
      /key_unavailable: the worker refused \(HTTP 403\): prod-app: an app may only decrypt/
    );
  });

  it("refuses an app another environment or bundle", async () => {
    const t = await withBundle();
    const staging = await create(t.w.client(t.editorToken), "staging");
    expect(await errorOf(openBundle(staging, t.w.client(t.appToken)))).toMatch(
      /HTTP 403.*not allowed for environment staging/
    );
    const other = await create(t.w.client(t.editorToken));
    expect(await errorOf(openBundle(other, t.w.client(t.appToken)))).toMatch(
      /HTTP 403.*not allowed for bundle/
    );
  });

  it("refuses unknown and missing tokens", async () => {
    const t = await withBundle();
    expect(await errorOf(openBundle(t.text, t.w.client(newToken())))).toMatch(
      /HTTP 401\): unknown credentials/
    );
    const res = await t.w.raw("v1/decrypt", "", {});
    expect(res.status).toBe(401);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("pins a client to addresses", async () => {
    const t = await withBundle();
    const pinned = { ...t.app, ips: ["203.0.113.0/24", "2001:db8::/32"] };
    t.env.KEYSEAL_ACCESS = JSON.stringify({ clients: [t.editor, pinned] });
    const open = (ip?: string) =>
      errorOf(openBundle(t.text, t.w.client(t.appToken, ip)));
    expect(await open("203.0.113.9")).toBe("ok");
    expect(await open("2001:db8:1::5")).toBe("ok");
    expect(await open("198.51.100.1")).toMatch(/not allowed from this address/);
    expect(await open()).toMatch(/not allowed from this address/);
  });

  it("revokes older epochs with minEpoch", async () => {
    const t = await withBundle();
    const ed = await BundleEditor.open(t.text, t.w.client(t.editorToken));
    await ed.rekey(CURRENT_WORKER_KEY);
    const next = await ed.seal();
    t.env.KEYSEAL_ACCESS = JSON.stringify({
      clients: [t.editor, t.app],
      minEpoch: { [t.id]: 2 },
    });
    expect(await errorOf(openBundle(next, t.w.client(t.appToken)))).toBe("ok");
    expect(await errorOf(openBundle(t.text, t.w.client(t.appToken)))).toMatch(
      /HTTP 403\): epoch 1 of this bundle is revoked/
    );
  });

  it("rotates the Worker's key: old bundles still open, rekey moves them", async () => {
    const t = await withBundle();
    const newKey = generateLocalKey();
    t.env.KEYSEAL_KEY = `${newKey}\n${t.key}`;
    expect(await errorOf(openBundle(t.text, t.w.client(t.appToken)))).toBe(
      "ok"
    );
    const ed = await BundleEditor.open(t.text, t.w.client(t.editorToken));
    await ed.rekey(CURRENT_WORKER_KEY);
    const moved = await ed.seal();
    expect(parseBundle(moved).key.keyId).toBe(await localKeyId(newKey));
    t.env.KEYSEAL_KEY = newKey;
    expect(await errorOf(openBundle(moved, t.w.client(t.appToken)))).toBe("ok");
    expect(await errorOf(openBundle(t.text, t.w.client(t.appToken)))).toMatch(
      /HTTP 404\): this worker has no key/
    );
  });

  it("answers 422 for a changed wrapped key and 400 for a bad body", async () => {
    const t = await withBundle();
    const b = parseBundle(t.text);
    const wrapped = new Uint8Array(b64uDecode(b.key.wrapped) ?? []);
    wrapped[20] = (wrapped[20] ?? 0) ^ 1;
    const context = { bundleId: b.id, env: b.env, epoch: 1 };
    const tampered = await t.w.raw("v1/decrypt", t.appToken, {
      keyId: b.key.keyId,
      wrapped: b64uEncode(wrapped),
      context,
    });
    expect(tampered.status).toBe(422);
    const bad = await t.w.raw("v1/decrypt", t.appToken, {
      keyId: b.key.keyId,
      wrapped: "short",
      context,
    });
    expect(bad.status).toBe(400);
    const current = await t.w.raw("v1/decrypt", t.appToken, {
      keyId: CURRENT_WORKER_KEY,
      wrapped: b.key.wrapped,
      context,
    });
    expect(current.status).toBe(400);
  });

  it("fails closed on a bad config without echoing secrets", async () => {
    const t = await withBundle();
    t.env.KEYSEAL_ACCESS = JSON.stringify({
      clients: [{ ...t.app, token: t.appToken }],
    });
    const res = await t.w.raw("v1/decrypt", t.appToken, {});
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({
      error: 500,
      message: "worker misconfigured",
    });
    expect(String(t.w.records.at(-1)?.reason)).toMatch(
      /never the token itself/
    );

    const unset = setup({ KEYSEAL_KEY: t.key });
    expect((await unset.raw("v1/decrypt", t.appToken, {})).status).toBe(500);
    expect(unset.records.at(-1)?.reason).toBe(
      "config: KEYSEAL_ACCESS is not set"
    );

    t.env.KEYSEAL_ACCESS = JSON.stringify({ clients: [t.app] });
    t.env.KEYSEAL_KEY = "keyseal_local_secret-but-malformed";
    expect((await t.w.raw("v1/decrypt", t.appToken, {})).status).toBe(500);
    expect(JSON.stringify(t.w.records)).not.toContain("secret-but-malformed");
  });
});

describe("KEYSEAL_ACCESS parsing", () => {
  const hash = `sha256:${"A".repeat(43)}`;
  const id = "B".repeat(22);
  const bad = (v: unknown) => () => parseAccess(v);

  it("accepts a JSON string or an object", () => {
    const v = {
      clients: [
        { name: "a", role: "app", env: "production", bundle: id, token: hash },
      ],
      minEpoch: { [id]: 2 },
    };
    expect(parseAccess(JSON.stringify(v)).minEpoch.get(id)).toBe(2);
    expect(parseAccess(v).clients[0]?.bundles).toEqual([id]);
  });

  it("rejects anything loose", () => {
    const app = { name: "a", role: "app", env: "production", bundle: id };
    expect(bad("{")).toThrow(/not valid JSON/);
    expect(bad({ clients: [{ ...app }] })).toThrow(/exactly one of token/);
    expect(
      bad({ clients: [{ ...app, bundle: undefined, token: hash }] })
    ).toThrow(/an app needs env and bundle/);
    expect(bad({ clients: [{ ...app, token: hash, extra: 1 }] })).toThrow(
      /unknown field "extra"/
    );
    expect(
      bad({ clients: [{ ...app, token: hash, ips: ["10.0.0.0/33"] }] })
    ).toThrow(/ips is not valid/);
    expect(
      bad({
        clients: [{ ...app, oidc: { issuer: "https://x", audience: "y" } }],
      })
    ).toThrow(/subject is required unless claims is set/);
    expect(
      bad({
        clients: [
          {
            ...app,
            oidc: { issuer: "https://x", audience: "y", claims: {} },
          },
        ],
      })
    ).toThrow(/subject is required unless claims is set/);
    expect(
      bad({
        clients: [
          { ...app, oidc: { issuer: "http://x", audience: "y", subject: "z" } },
        ],
      })
    ).toThrow(/must be https/);
    expect(bad({ clients: [], minEpoch: { [id]: 0 } })).toThrow(/minEpoch/);
  });
});

describe("worker client", () => {
  it("only talks https, except to localhost", () => {
    expect(() =>
      worker({ url: "http://keyseal.example.com", token: "t" })
    ).toThrow(/must use https/);
    expect(() =>
      worker({ url: "https://u:p@example.com", token: "t" })
    ).toThrow(/no credentials/);
    expect(() =>
      worker({ url: "https://example.com/?a=1", token: "t" })
    ).toThrow(/no credentials, query/);
    expect(() =>
      worker({ url: "http://localhost:8787", token: "t" })
    ).not.toThrow();
  });

  it("rejects a malformed answer", async () => {
    const p = worker({
      url: BASE,
      token: "t",
      fetch: async () =>
        Response.json({ plaintext: b64uEncode(new Uint8Array(16)) }),
    });
    const ctx = { bundleId: "B".repeat(22), env: "production", epoch: 1 };
    expect(
      await errorOf(p.decryptDataKey("A".repeat(22), new Uint8Array(60), ctx))
    ).toMatch(/invalid data key/);
    expect(
      await errorOf(p.decryptDataKey("../../etc", new Uint8Array(60), ctx))
    ).toMatch(/not a worker key id/);
  });

  it("reports an unreachable Worker without the token", async () => {
    const p = worker({
      url: BASE,
      token: "keyseal_wt_do-not-print",
      fetch: async () => {
        throw new TypeError("connection refused");
      },
    });
    const ctx = { bundleId: "B".repeat(22), env: "production", epoch: 1 };
    const msg = await errorOf(p.generateDataKey("current", ctx));
    expect(msg).toMatch(/could not reach the worker/);
    expect(msg).not.toContain("do-not-print");
  });
});

describe("keyseal policy for a Worker bundle", () => {
  it("prints an app entry and revokes older epochs", async () => {
    const t = await withBundle();
    const ed = await BundleEditor.open(t.text, t.w.client(t.editorToken));
    await ed.rekey(CURRENT_WORKER_KEY);
    const b = parseBundle(await ed.seal());
    expect(workerAccess(b)).toEqual({
      clients: [
        {
          name: "production-app",
          role: "app",
          env: "production",
          bundle: b.id,
          token: "sha256:PASTE_FROM_KEYSEAL_TOKEN",
        },
      ],
      minEpoch: { [b.id]: 2 },
    });
    // The placeholder must fail closed until it's replaced.
    expect(() => parseAccess(workerAccess(b))).toThrow(/sha256/);
  });
});

// OIDC: a fake issuer with a real signing key.

interface Issuer {
  iss: string;
  fetch: typeof globalThis.fetch;
  sign: (
    claims: Record<string, unknown>,
    header?: Record<string, unknown>
  ) => Promise<string>;
  fetched: string[];
}

async function issuer(alg: "RS256" | "ES256"): Promise<Issuer> {
  const iss = "https://oidc.example.com";
  const params =
    alg === "RS256"
      ? {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        }
      : { name: "ECDSA", namedCurve: "P-256" };
  const pair = (await subtle.generateKey(params, true, [
    "sign",
    "verify",
  ])) as webcrypto.CryptoKeyPair;
  const jwk = await subtle.exportKey("jwk", pair.publicKey);
  const fetched: string[] = [];
  return {
    iss,
    fetched,
    fetch: async (input) => {
      const href = String(input instanceof Request ? input.url : input);
      fetched.push(href);
      if (href === `${iss}/.well-known/openid-configuration`)
        return Response.json({ issuer: iss, jwks_uri: `${iss}/jwks` });
      if (href === `${iss}/jwks`)
        return Response.json({ keys: [{ ...jwk, kid: "k1", use: "sig" }] });
      return new Response("not found", { status: 404 });
    },
    sign: async (claims, header = {}) => {
      const enc = (o: object) => b64uEncode(utf8(JSON.stringify(o)));
      const head = enc({ alg, kid: "k1", typ: "JWT", ...header });
      const body = enc(claims);
      const sig = await subtle.sign(
        alg === "RS256"
          ? "RSASSA-PKCS1-v1_5"
          : { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        utf8(`${head}.${body}`)
      );
      return `${head}.${body}.${b64uEncode(new Uint8Array(sig))}`;
    },
  };
}

describe("OIDC clients", () => {
  for (const alg of ["RS256", "ES256"] as const) {
    it(`verifies ${alg} tokens and checks every claim`, async () => {
      const idp = await issuer(alg);
      const now = Date.parse("2026-10-22T12:00:00Z");
      const sec = now / 1000;
      const t = await withBundle();
      const oidcApp = {
        name: "vercel-prod",
        role: "app",
        env: "production",
        bundle: t.id,
        oidc: {
          issuer: idp.iss,
          audience: "https://keyseal.example.workers.dev",
          subject: "owner:acme:project:web:environment:production",
          claims: { environment: "production" },
        },
      };
      const env: KeysealWorkerEnv = {
        KEYSEAL_KEY: t.key,
        KEYSEAL_ACCESS: JSON.stringify({ clients: [oidcApp] }),
      };
      const w = setup(env, { fetch: idp.fetch, now: () => now });
      const good = {
        iss: idp.iss,
        aud: [oidcApp.oidc.audience],
        sub: oidcApp.oidc.subject,
        environment: "production",
        iat: sec,
        exp: sec + 300,
      };
      const open = async (claims: object, header?: Record<string, unknown>) =>
        errorOf(
          openBundle(
            t.text,
            w.client(await idp.sign(claims as Record<string, unknown>, header))
          )
        );

      expect(await open(good)).toBe("ok");
      expect(w.records.at(-1)?.client).toBe("vercel-prod");
      expect(await open({ ...good, aud: "someone-else" })).toMatch(/HTTP 401/);
      expect(
        await open({
          ...good,
          sub: "owner:acme:project:web:environment:preview",
        })
      ).toMatch(/HTTP 401/);
      expect(await open({ ...good, environment: "preview" })).toMatch(
        /HTTP 401/
      );
      expect(await open({ ...good, exp: sec - 120 })).toMatch(/HTTP 401/);
      expect(await open({ ...good, nbf: sec + 120 })).toMatch(/HTTP 401/);
      expect(await open(good, { alg: "none" })).toMatch(/HTTP 401/);
      expect(await open(good, { crit: ["exp"] })).toMatch(/HTTP 401/);
      expect(await open(good, { kid: "unknown" })).toMatch(/HTTP 401/);

      // A valid signature over other claims is not a valid token.
      const real = await idp.sign(good);
      const [h, , s] = real.split(".");
      const forged = `${h}.${b64uEncode(utf8(JSON.stringify({ ...good, sub: "x" })))}.${s}`;
      expect(await errorOf(openBundle(t.text, w.client(forged)))).toMatch(
        /HTTP 401/
      );

      // Discovery and keys are fetched once and cached.
      const before = idp.fetched.length;
      expect(await open(good)).toBe("ok");
      expect(idp.fetched.length).toBe(before);
    });
  }

  it("matches on claims alone when sub changes per instance (Fly)", async () => {
    const idp = await issuer("ES256");
    const t = await withBundle();
    const audience = "https://keyseal.example.workers.dev";
    const flyApp = {
      name: "fly-prod",
      role: "app",
      env: "production",
      bundle: t.id,
      oidc: { issuer: idp.iss, audience, claims: { app_name: "web" } },
    };
    const w = setup(
      {
        KEYSEAL_KEY: t.key,
        KEYSEAL_ACCESS: JSON.stringify({ clients: [flyApp] }),
      },
      { fetch: idp.fetch }
    );
    const open = async (sub: string, appName: string) =>
      errorOf(
        openBundle(
          t.text,
          w.client(
            await idp.sign({
              iss: idp.iss,
              aud: audience,
              sub,
              app_name: appName,
              exp: Date.now() / 1000 + 60,
            })
          )
        )
      );
    expect(await open("acme:web:machine-a", "web")).toBe("ok");
    expect(await open("acme:web:machine-b", "web")).toBe("ok");
    expect(await open("acme:api:machine-c", "api")).toMatch(/HTTP 401/);
  });

  it("never fetches an issuer the config doesn't name", async () => {
    const idp = await issuer("ES256");
    const t = await withBundle();
    const w = setup(
      {
        KEYSEAL_KEY: t.key,
        KEYSEAL_ACCESS: JSON.stringify({ clients: [t.app] }),
      },
      { fetch: idp.fetch }
    );
    const token = await idp.sign({
      iss: "https://attacker.example.com",
      aud: "x",
      sub: "y",
      exp: Date.now() / 1000 + 60,
    });
    expect(await errorOf(openBundle(t.text, w.client(token)))).toMatch(
      /HTTP 401/
    );
    expect(idp.fetched).toEqual([]);
  });
});
