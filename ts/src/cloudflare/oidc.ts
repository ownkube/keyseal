// Verifies platform OIDC tokens (Vercel, Fly, GitHub Actions and so on)
// against the issuer's published keys, so an app can prove who it is with
// no secret stored on the platform. Only issuers named in KEYSEAL_ACCESS
// are ever fetched; the token can't point the Worker anywhere else.

import { b64uDecode, fromUtf8, utf8 } from "../encoding.ts";

const subtle = globalThis.crypto.subtle;

/** Clock skew tolerated on exp and nbf, in seconds. */
const SKEW = 60;
const JWKS_TTL_MS = 10 * 60_000;
const REFETCH_MIN_MS = 60_000;

export class AuthError extends Error {}

type Obj = Record<string, unknown>;

interface Jwk {
  kty?: string;
  kid?: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
}

interface CachedJwks {
  keys: Jwk[];
  at: number;
}

export interface OidcDeps {
  fetch: typeof globalThis.fetch;
  now: () => number;
}

function json(part: string | undefined): Obj | null {
  const b = part === undefined ? null : b64uDecode(part);
  if (!b) return null;
  try {
    const v: unknown = JSON.parse(fromUtf8(b));
    return typeof v === "object" && v !== null && !Array.isArray(v)
      ? (v as Obj)
      : null;
  } catch {
    return null;
  }
}

export function looksLikeJwt(token: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token);
}

/** The unverified issuer, only to pick which configured rule applies. */
export function peekIssuer(token: string): string | null {
  const iss = json(token.split(".")[1])?.iss;
  return typeof iss === "string" ? iss : null;
}

async function getJson(
  deps: OidcDeps,
  href: string,
  what: string
): Promise<Obj> {
  let res: Response;
  try {
    res = await deps.fetch(href, {
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    throw new AuthError(`could not fetch the ${what}`);
  }
  if (!res.ok) throw new AuthError(`the ${what} returned HTTP ${res.status}`);
  const v: unknown = await res.json().catch(() => null);
  if (typeof v !== "object" || v === null)
    throw new AuthError(`the ${what} is not JSON`);
  return v as Obj;
}

export class JwksCache {
  readonly #cache = new Map<string, CachedJwks>();
  readonly #deps: OidcDeps;

  constructor(deps: OidcDeps) {
    this.#deps = deps;
  }

  async #fetch(issuer: string): Promise<Jwk[]> {
    const conf = await getJson(
      this.#deps,
      `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
      "issuer's OpenID configuration"
    );
    // The issuer must claim itself, so a mirror can't stand in for it.
    if (conf.issuer !== issuer)
      throw new AuthError("the issuer's configuration names another issuer");
    const uri = conf.jwks_uri;
    if (typeof uri !== "string" || !uri.startsWith("https://"))
      throw new AuthError("the issuer's jwks_uri is not https");
    const jwks = await getJson(this.#deps, uri, "issuer's keys");
    const keys = Array.isArray(jwks.keys) ? (jwks.keys as Jwk[]) : [];
    this.#cache.set(issuer, { keys, at: this.#deps.now() });
    return keys;
  }

  async key(
    issuer: string,
    kid: string | undefined,
    alg: string
  ): Promise<Jwk> {
    const pick = (keys: Jwk[]): Jwk | undefined => {
      const usable = keys.filter(
        (k) =>
          (k.use === undefined || k.use === "sig") &&
          (k.alg === undefined || k.alg === alg) &&
          k.kty === (alg === "RS256" ? "RSA" : "EC")
      );
      if (kid !== undefined) return usable.find((k) => k.kid === kid);
      return usable.length === 1 ? usable[0] : undefined;
    };
    const cached = this.#cache.get(issuer);
    const now = this.#deps.now();
    if (cached && now - cached.at < JWKS_TTL_MS) {
      const k = pick(cached.keys);
      // An unknown kid may mean the issuer rotated; refetch, but not often.
      if (k || now - cached.at < REFETCH_MIN_MS) {
        if (!k) throw new AuthError("no matching signing key");
        return k;
      }
    }
    const k = pick(await this.#fetch(issuer));
    if (!k) throw new AuthError("no matching signing key");
    return k;
  }
}

async function verifySignature(
  jwk: Jwk,
  alg: string,
  signed: Uint8Array<ArrayBuffer>,
  sig: Uint8Array<ArrayBuffer>
): Promise<boolean> {
  try {
    if (alg === "RS256") {
      const key = await subtle.importKey(
        "jwk",
        { kty: "RSA", n: jwk.n, e: jwk.e },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
      );
      return await subtle.verify("RSASSA-PKCS1-v1_5", key, sig, signed);
    }
    if (jwk.crv !== "P-256" || sig.length !== 64) return false;
    const key = await subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    return await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      sig,
      signed
    );
  } catch {
    return false;
  }
}

/**
 * Verify a JWT from `issuer` and return its claims. Checks the signature
 * (RS256 or ES256 only), iss, aud, exp and nbf. The caller checks sub and
 * any other claims against its rule.
 */
export async function verifyJwt(
  token: string,
  issuer: string,
  audience: string,
  jwks: JwksCache,
  now: number
): Promise<Obj> {
  const [h, p, s] = token.split(".");
  const header = json(h);
  const claims = json(p);
  const sig = s === undefined ? null : b64uDecode(s);
  if (!header || !claims || !sig || h === undefined || p === undefined)
    throw new AuthError("malformed token");
  const alg = header.alg;
  if (alg !== "RS256" && alg !== "ES256")
    throw new AuthError("unsupported token algorithm");
  if (header.crit !== undefined)
    throw new AuthError("unsupported token header");
  const kid = typeof header.kid === "string" ? header.kid : undefined;
  const jwk = await jwks.key(issuer, kid, alg);
  if (!(await verifySignature(jwk, alg, utf8(`${h}.${p}`), sig)))
    throw new AuthError("bad token signature");

  const t = now / 1000;
  if (claims.iss !== issuer) throw new AuthError("wrong token issuer");
  const aud = claims.aud;
  if (!(aud === audience || (Array.isArray(aud) && aud.includes(audience))))
    throw new AuthError("wrong token audience");
  if (typeof claims.exp !== "number" || t >= claims.exp + SKEW)
    throw new AuthError("expired token");
  if (typeof claims.nbf === "number" && t < claims.nbf - SKEW)
    throw new AuthError("token not valid yet");
  return claims;
}
