// The Worker's access config (KEYSEAL_ACCESS): who may ask for which
// bundles, from where, and which key epochs are revoked. Parsed strictly,
// because a typo here must fail closed, never open.

import { b64uDecode, type Bytes } from "../encoding.ts";
import { isValidEnv } from "../format.ts";

export type Role = "app" | "editor";

export interface OidcRule {
  issuer: string;
  audience: string;
  /** The exact `sub`, or undefined when `claims` pins the workload. */
  subject?: string;
  /** Extra claims that must equal these values exactly. */
  claims: Record<string, string>;
}

export interface Client {
  name: string;
  role: Role;
  /** null means any environment (editors only). */
  envs: string[] | null;
  /** null means any bundle (editors only). */
  bundles: string[] | null;
  /** null means any address. */
  ips: Cidr[] | null;
  tokenHash?: Bytes;
  oidc?: OidcRule;
}

export interface Access {
  clients: Client[];
  /** Bundle id to the lowest epoch still accepted. */
  minEpoch: Map<string, number>;
}

export const BUNDLE_ID_RE: RegExp = /^[A-Za-z0-9_-]{22}$/;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const TOKEN_HASH_RE = /^sha256:([A-Za-z0-9_-]{43})$/;

export class ConfigError extends Error {}

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function only(o: Obj, allowed: readonly string[], where: string): void {
  for (const k of Object.keys(o)) {
    if (!allowed.includes(k))
      throw new ConfigError(`${where}: unknown field "${k}"`);
  }
}

function list(
  v: unknown,
  where: string,
  check: (s: string) => boolean
): string[] | null {
  if (v === undefined) return null;
  const arr = typeof v === "string" ? [v] : v;
  if (
    !Array.isArray(arr) ||
    arr.length === 0 ||
    !arr.every((s) => typeof s === "string" && check(s))
  ) {
    throw new ConfigError(`${where} is not valid`);
  }
  return arr as string[];
}

function httpsUrl(v: unknown, where: string): string {
  if (typeof v !== "string") throw new ConfigError(`${where} is not valid`);
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new ConfigError(`${where} is not a URL`);
  }
  if (u.protocol !== "https:") throw new ConfigError(`${where} must be https`);
  return v;
}

function parseOidc(v: unknown, where: string): OidcRule {
  if (!isObj(v)) throw new ConfigError(`${where} is not an object`);
  only(v, ["issuer", "audience", "subject", "claims"], where);
  const str = (k: string): string => {
    const s = v[k];
    if (typeof s !== "string" || s === "")
      throw new ConfigError(`${where}.${k} is required`);
    return s;
  };
  const claims: Record<string, string> = {};
  if (v.claims !== undefined) {
    if (!isObj(v.claims))
      throw new ConfigError(`${where}.claims is not an object`);
    for (const [k, c] of Object.entries(v.claims)) {
      if (typeof c !== "string")
        throw new ConfigError(`${where}.claims.${k} must be a string`);
      claims[k] = c;
    }
  }
  // One of the two is required: without either, every workload the issuer
  // serves would match. Claims alone suit issuers whose sub changes per
  // instance (Fly puts the machine name in it).
  if (v.subject === undefined && Object.keys(claims).length === 0) {
    throw new ConfigError(`${where}.subject is required unless claims is set`);
  }
  return {
    issuer: httpsUrl(v.issuer, `${where}.issuer`),
    audience: str("audience"),
    ...(v.subject === undefined ? {} : { subject: str("subject") }),
    claims,
  };
}

function parseClient(v: unknown, i: number): Client {
  const where = `clients[${i}]`;
  if (!isObj(v)) throw new ConfigError(`${where} is not an object`);
  only(v, ["name", "role", "env", "bundle", "ips", "token", "oidc"], where);
  if (typeof v.name !== "string" || !NAME_RE.test(v.name))
    throw new ConfigError(`${where}.name is not valid`);
  const w = `clients["${v.name}"]`;
  if (v.role !== "app" && v.role !== "editor")
    throw new ConfigError(`${w}.role must be "app" or "editor"`);
  const envs = list(v.env, `${w}.env`, isValidEnv);
  const bundles = list(v.bundle, `${w}.bundle`, (s) => BUNDLE_ID_RE.test(s));
  if (v.role === "app" && (!envs || !bundles)) {
    throw new ConfigError(`${w}: an app needs env and bundle`);
  }
  const ips = list(v.ips, `${w}.ips`, (s) => parseCidr(s) !== null);
  const client: Client = {
    name: v.name,
    role: v.role,
    envs,
    bundles,
    ips: ips?.map((s) => parseCidr(s) as Cidr) ?? null,
  };
  if ((v.token === undefined) === (v.oidc === undefined)) {
    throw new ConfigError(`${w}: set exactly one of token or oidc`);
  }
  if (v.token !== undefined) {
    const m = typeof v.token === "string" ? TOKEN_HASH_RE.exec(v.token) : null;
    const hash = m?.[1] ? b64uDecode(m[1]) : null;
    if (hash?.length !== 32) {
      throw new ConfigError(
        `${w}.token must be "sha256:..." as printed by \`keyseal token\`, never the token itself`
      );
    }
    client.tokenHash = hash;
  } else {
    client.oidc = parseOidc(v.oidc, `${w}.oidc`);
  }
  return client;
}

export function parseAccess(raw: unknown): Access {
  let v = raw;
  if (typeof raw === "string") {
    try {
      v = JSON.parse(raw);
    } catch {
      throw new ConfigError("KEYSEAL_ACCESS is not valid JSON");
    }
  }
  if (!isObj(v)) throw new ConfigError("KEYSEAL_ACCESS is not set");
  only(v, ["clients", "minEpoch"], "KEYSEAL_ACCESS");
  if (!Array.isArray(v.clients))
    throw new ConfigError("KEYSEAL_ACCESS.clients is not a list");
  const clients = v.clients.map(parseClient);
  const names = new Set<string>();
  for (const c of clients) {
    if (names.has(c.name))
      throw new ConfigError(`two clients are named "${c.name}"`);
    names.add(c.name);
  }
  const minEpoch = new Map<string, number>();
  if (v.minEpoch !== undefined) {
    if (!isObj(v.minEpoch)) throw new ConfigError("minEpoch is not an object");
    for (const [id, n] of Object.entries(v.minEpoch)) {
      if (
        !BUNDLE_ID_RE.test(id) ||
        !Number.isSafeInteger(n) ||
        (n as number) < 1
      )
        throw new ConfigError(`minEpoch["${id}"] is not valid`);
      minEpoch.set(id, n as number);
    }
  }
  return { clients, minEpoch };
}

// IP matching for CF-Connecting-IP.

export interface Cidr {
  bytes: Bytes;
  prefix: number;
}

function parseV4(s: string): Bytes | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i] ?? "";
    if (!/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255) return null;
    out[i] = Number(p);
  }
  return out;
}

function parseV6(s: string): Bytes | null {
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const groups = (h: string | undefined): string[] | null => {
    if (!h) return [];
    const g = h.split(":");
    return g.every((x) => /^[0-9a-fA-F]{1,4}$/.test(x)) ? g : null;
  };
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  if (!head || !tail) return null;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
  const all = [...head, ...Array<string>(fill).fill("0"), ...tail];
  const out = new Uint8Array(16);
  all.forEach((g, i) => {
    const n = Number.parseInt(g, 16);
    out[i * 2] = n >> 8;
    out[i * 2 + 1] = n & 0xff;
  });
  return out;
}

export function parseIp(s: string): Bytes | null {
  return s.includes(":") ? parseV6(s) : parseV4(s);
}

export function parseCidr(s: string): Cidr | null {
  const [ip, len, extra] = s.split("/");
  if (extra !== undefined || !ip) return null;
  const bytes = parseIp(ip);
  if (!bytes) return null;
  const max = bytes.length * 8;
  if (len === undefined) return { bytes, prefix: max };
  if (!/^\d{1,3}$/.test(len) || Number(len) > max) return null;
  return { bytes, prefix: Number(len) };
}

export function ipAllowed(ip: Bytes | null, cidrs: Cidr[]): boolean {
  if (!ip) return false;
  return cidrs.some((c) => {
    if (c.bytes.length !== ip.length) return false;
    for (let bit = 0; bit < c.prefix; bit++) {
      const mask = 0x80 >> (bit % 8);
      const i = bit >> 3;
      if (((c.bytes[i] ?? 0) & mask) !== ((ip[i] ?? 0) & mask)) return false;
    }
    return true;
  });
}
