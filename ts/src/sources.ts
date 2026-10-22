// Where a running app reads its bundle from. Polling a source you control
// (your bucket, your URL) is what lets secrets rotate without a deploy.

import { b64uEncode, utf8 } from "./encoding.ts";
import { KeysealError } from "./errors.ts";

export interface SourceRead {
  body: string;
  /** Opaque change marker, passed back on the next read. */
  etag?: string;
}

export interface Source {
  readonly description: string;
  /** True when the bundle can never change, so polling is pointless. */
  readonly static?: boolean;
  /** Resolve null when the bundle hasn't changed since `etag`. */
  read(etag?: string): Promise<SourceRead | null>;
}

async function digest(body: string): Promise<string> {
  const h = await globalThis.crypto.subtle.digest("SHA-256", utf8(body));
  return b64uEncode(new Uint8Array(h));
}

/** A bundle file on disk (Node, Bun, Deno). */
export function file(path: string): Source {
  return {
    description: path,
    async read(etag) {
      const { readFile } = await import("node:fs/promises");
      let body: string;
      try {
        body = await readFile(path, "utf8");
      } catch (cause) {
        throw new KeysealError("source_unavailable", `could not read ${path}`, {
          cause,
        });
      }
      const tag = await digest(body);
      return tag === etag ? null : { body, etag: tag };
    },
  };
}

export interface UrlOptions {
  headers?: Record<string, string>;
  /** Allow plain http (localhost is always allowed). */
  allowInsecure?: boolean;
  fetch?: typeof globalThis.fetch;
}

/** A bundle served over HTTPS. Uses If-None-Match, so polling is cheap. */
export function url(href: string, opts: UrlOptions = {}): Source {
  const u = new URL(href);
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (
    u.protocol !== "https:" &&
    !(u.protocol === "http:" && (local || opts.allowInsecure))
  ) {
    throw new KeysealError(
      "invalid_argument",
      `bundle URLs must use https (got ${u.protocol})`
    );
  }
  const doFetch = opts.fetch ?? globalThis.fetch;
  // Never echo credentials from the URL into errors or descriptions.
  const description = `${u.origin}${u.pathname}`;
  return {
    description,
    async read(etag) {
      let res: Response;
      try {
        res = await doFetch(href, {
          headers: {
            ...opts.headers,
            ...(etag ? { "if-none-match": etag } : {}),
          },
          cache: "no-store",
        });
      } catch (cause) {
        throw new KeysealError(
          "source_unavailable",
          `could not fetch ${description}`,
          { cause }
        );
      }
      if (res.status === 304) return null;
      if (!res.ok) {
        throw new KeysealError(
          "source_unavailable",
          `fetching ${description} returned HTTP ${res.status}`
        );
      }
      const body = await res.text();
      const tag = res.headers.get("etag") ?? (await digest(body));
      return tag === etag ? null : { body, etag: tag };
    },
  };
}

/** A bundle you already have in memory, e.g. imported at build time. */
export function inline(body: string): Source {
  let tag: string | undefined;
  return {
    description: "inline bundle",
    static: true,
    async read(etag) {
      tag ??= await digest(body);
      return tag === etag ? null : { body, etag: tag };
    },
  };
}
