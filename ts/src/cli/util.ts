import { mkdir, rename, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { KeysealError } from "../errors.ts";
import { parseS3Url, s3 } from "../s3.ts";
import { file, type Source, url } from "../sources.ts";

export class UsageError extends Error {}

const DURATION_RE = /^(\d+)(ms|s|m|h|d)$/;
const UNIT_MS: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

/** "90s", "15m", "24h", "7d" to milliseconds. */
export function parseDuration(s: string, flag: string): number {
  if (s === "0") return 0;
  const m = DURATION_RE.exec(s);
  if (!m?.[1] || !m[2]) {
    throw new UsageError(`${flag} takes a duration like 30s, 15m, 24h or 7d`);
  }
  return Number(m[1]) * (UNIT_MS[m[2]] ?? 0);
}

/** A date (2026-03-01, or a full timestamp) or a duration ago ("36h"). */
export function parseSince(s: string, now: number = Date.now()): number {
  if (DURATION_RE.test(s)) return now - parseDuration(s, "--stale-since");
  const t = Date.parse(s);
  if (Number.isNaN(t)) {
    throw new UsageError(
      "--stale-since takes a date like 2026-03-01 or a duration like 36h"
    );
  }
  return t;
}

/** A path, an https:// URL or an s3:// URL. */
export function sourceFor(spec: string, region: string | undefined): Source {
  if (spec.startsWith("s3://")) {
    return s3({ ...parseS3Url(spec), ...(region ? { region } : {}) });
  }
  if (/^https?:\/\//.test(spec)) return url(spec);
  return file(spec);
}

/** Write commands edit a local file, then you upload it. */
export function localBundle(path: string): Source {
  if (/^(s3|https?):\/\//.test(path)) {
    throw new UsageError(
      `${path} is not a local file: edit a local bundle, then upload it`
    );
  }
  return file(path);
}

export async function readText(source: Source): Promise<string> {
  const r = await source.read();
  if (!r)
    throw new KeysealError(
      "source_unavailable",
      `${source.description} returned nothing`
    );
  return r.body;
}

/** Write via a temp file and rename, so a crash never leaves half a bundle. */
export async function writeAtomic(path: string, text: string): Promise<void> {
  let mode = 0o644;
  try {
    mode = (await stat(path)).mode & 0o777;
  } catch {
    // new file
  }
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, text, { mode });
  await rename(tmp, path);
}

export async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Read a secret value without it touching argv or shell history: piped
 * stdin, or a hidden prompt on a terminal. One trailing newline from piped
 * input is dropped unless `raw`.
 */
export async function readValue(name: string, raw: boolean): Promise<string> {
  if (process.stdin.isTTY) return promptHidden(`Value for ${name}: `);
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  return raw ? text : text.replace(/\r?\n$/, "");
}

function promptHidden(question: string): Promise<string> {
  const { stdin, stderr } = process;
  stderr.write(question);
  stdin.setRawMode(true);
  stdin.setEncoding("utf8");
  stdin.resume();
  return new Promise((resolve, reject) => {
    let buf = "";
    const done = (fn: () => void): void => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      stderr.write("\n");
      fn();
    };
    const onData = (chunk: string): void => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return done(() => resolve(buf));
        if (ch === "\u0003" || ch === "\u0004") {
          return done(() => reject(new UsageError("cancelled")));
        }
        if (ch === "\u007f" || ch === "\b") buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    stdin.on("data", onData);
  });
}

function dotenvQuote(v: string): string {
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r/g, "\\r").replace(/\n/g, "\\n")}"`;
}

function shellQuote(v: string): string {
  return `'${v.replace(/'/g, "'\\''")}'`;
}

export function formatExport(
  env: Record<string, string>,
  format: string
): string {
  const names = Object.keys(env).sort();
  switch (format) {
    case "dotenv":
      return names.map((n) => `${n}=${dotenvQuote(env[n] ?? "")}\n`).join("");
    case "shell":
      return names
        .map((n) => `export ${n}=${shellQuote(env[n] ?? "")}\n`)
        .join("");
    case "json":
      return `${JSON.stringify(Object.fromEntries(names.map((n) => [n, env[n]])), null, 2)}\n`;
    default:
      throw new UsageError("--format is one of dotenv, shell, json");
  }
}

export function ago(iso: string, now: number = Date.now()): string {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 120) return `${s}s ago`;
  if (s < 7200) return `${Math.round(s / 60)}m ago`;
  if (s < 172800) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function table(rows: string[][]): string {
  const widths: number[] = [];
  for (const r of rows)
    r.forEach((c, i) => (widths[i] = Math.max(widths[i] ?? 0, c.length)));
  return rows
    .map((r) =>
      r
        .map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i] ?? 0)))
        .join("  ")
    )
    .join("\n");
}
