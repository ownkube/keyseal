// A bundle in an S3 bucket you own. Upload a new bundle and every app polling
// it switches to the new values within one poll interval, no deploy needed.

import {
  GetObjectCommand,
  S3Client,
  type S3ClientConfig,
} from "@aws-sdk/client-s3";
import { KeysealError } from "./errors.ts";
import type { Source } from "./sources.ts";

export interface S3Options {
  bucket: string;
  key: string;
  region?: string;
  client?: S3Client;
  clientConfig?: S3ClientConfig;
}

/** Parse `s3://bucket/path/to/bundle.ks.json`. */
export function parseS3Url(href: string): { bucket: string; key: string } {
  const m = /^s3:\/\/([^/]+)\/(.+)$/.exec(href);
  if (!m?.[1] || !m[2]) {
    throw new KeysealError(
      "invalid_argument",
      `expected s3://bucket/key, got ${href}`
    );
  }
  return { bucket: m[1], key: m[2] };
}

export function s3(opts: S3Options | string): Source {
  const o: S3Options = typeof opts === "string" ? parseS3Url(opts) : opts;
  const client =
    o.client ??
    new S3Client({
      ...o.clientConfig,
      ...(o.region ? { region: o.region } : {}),
    });
  const description = `s3://${o.bucket}/${o.key}`;
  return {
    description,
    async read(etag) {
      try {
        const res = await client.send(
          new GetObjectCommand({
            Bucket: o.bucket,
            Key: o.key,
            ...(etag ? { IfNoneMatch: etag } : {}),
          })
        );
        const body = await res.Body?.transformToString("utf-8");
        if (body === undefined) {
          throw new Error("empty response body");
        }
        return { body, ...(res.ETag ? { etag: res.ETag } : {}) };
      } catch (cause) {
        const status = (cause as { $metadata?: { httpStatusCode?: number } })
          .$metadata?.httpStatusCode;
        if (status === 304 || (cause as Error).name === "NotModified") {
          return null;
        }
        throw new KeysealError(
          "source_unavailable",
          `could not read ${description} (${(cause as Error).name ?? "error"})`,
          { cause }
        );
      }
    },
  };
}
