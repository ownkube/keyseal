#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseArgs, parseEnv } from "node:util";
import pkg from "../package.json" with { type: "json" };
import { BundleEditor, openBundle } from "./bundle.ts";
import {
  awsKeys,
  findLocalKey,
  newLocalKey,
  newWorkerToken,
  providerFor,
  workerKeys,
} from "./cli/keys.ts";
import { bundlePolicy, workerAccess } from "./cli/policy.ts";
import { runCommand } from "./cli/run.ts";
import {
  ago,
  exists,
  formatExport,
  localBundle,
  parseDuration,
  parseSince,
  readText,
  readValue,
  sourceFor,
  table,
  UsageError,
  writeAtomic,
} from "./cli/util.ts";
import { KeysealError } from "./errors.ts";
import {
  type Bundle,
  isValidName,
  parseBundle,
  sortedNames,
} from "./format.ts";
import type { KeyProvider } from "./keys.ts";
import { generateLocalKey } from "./local.ts";
import { CURRENT_WORKER_KEY } from "./worker.ts";

const HELP = `keyseal ${pkg.version}: encrypted secrets in your repo, unlocked by a key the platform never holds

Usage: keyseal <command> <bundle> [args] [flags]

Write (bundle is a local file):
  init <file> --env <env> --kms-key <key>   create an empty bundle sealed with AWS KMS
  init <file> --env <env> --local           ...or with a new local key, saved in ~/.config/keyseal/keys
  init <file> --env <env> --worker <url>    ...or by your keyseal Worker (token in KEYSEAL_WORKER_TOKEN)
  set <file> <NAME> [--grace 24h]           set a secret (value from stdin or a hidden prompt)
  rotate <file> <NAME> [--grace 24h]        set a secret, keeping the old value for the grace window
  import <file> <dotenv-file> [--grace 24h] set every value in a .env file (prints names only)
  rm <file> <NAME>                          remove a secret
  rekey <file> [--kms-key <key> | --local | --worker <url>]
                                            re-encrypt everything under a fresh data key (next epoch),
                                            optionally under a new KMS key, local key or Worker

Read (bundle is a file, https:// URL or s3://bucket/key):
  policy <file> [--role app|editor] [--s3 s3://bucket/key]
                                            print the IAM policy for an AWS KMS bundle, or the
                                            KEYSEAL_ACCESS entry for a Worker bundle, revoking
                                            every older epoch (no network call)
  key <bundle>                              print the local key a bundle is sealed with, to set
                                            as KEYSEAL_KEY on your platform

Worker setup (prints secrets; pipe them straight into wrangler or your platform):
  key --new                                 print a new key for \`wrangler secret put KEYSEAL_KEY\`
  token                                     print a new Worker token; its hash for KEYSEAL_ACCESS
                                            goes to stderr
  ls <bundle>                               list names and rotation times (no decryption)
  status <bundle> [--stale-since <when>]    verify the bundle; with --stale-since, list secrets
                                            not rotated since a date or duration and exit 1
  get <bundle> <NAME>                       print one value
  export <bundle> [--format dotenv|shell|json]
  run <bundle> [--watch] [--poll 30s] -- <command...>
                                            run a command with the secrets as env vars;
                                            --watch restarts it when secrets rotate

Flags:
  --env <env>          refuse bundles for any other environment (read commands)
  --min-version <n>    refuse bundles older than this version (read commands)
  --region <region>    AWS region when the key id isn't an ARN
  --worker <url>       your keyseal Worker (default KEYSEAL_WORKER_URL)
  --raw                keep a trailing newline from piped input
  -h, --help           show this help
  -v, --version        show the version
`;

const OPTIONS = {
  env: { type: "string" },
  "kms-key": { type: "string" },
  local: { type: "boolean" },
  worker: { type: "string" },
  new: { type: "boolean" },
  region: { type: "string" },
  grace: { type: "string" },
  raw: { type: "boolean" },
  format: { type: "string" },
  "stale-since": { type: "string" },
  watch: { type: "boolean" },
  poll: { type: "string" },
  "stop-timeout": { type: "string" },
  "min-version": { type: "string" },
  role: { type: "string" },
  s3: { type: "string" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
} as const;

function out(text: string): void {
  process.stdout.write(text.endsWith("\n") ? text : `${text}\n`);
}

function note(text: string): void {
  process.stderr.write(`${text}\n`);
}

function noteLocalKey(keyFile: string, bundle: string): void {
  note(
    `Saved the key to ${keyFile}. Back it up (a password manager works): without it nobody can open this bundle`
  );
  note(
    `On your platform, set KEYSEAL_KEY to the output of \`keyseal key ${bundle}\``
  );
}

function need(v: string | undefined, what: string): string {
  if (!v) throw new UsageError(`missing ${what}`);
  return v;
}

async function main(argv: string[]): Promise<number> {
  const dash = argv.indexOf("--");
  const command = dash >= 0 ? argv.slice(dash + 1) : [];
  const { values: f, positionals } = parseArgs({
    args: dash >= 0 ? argv.slice(0, dash) : argv,
    options: OPTIONS,
    allowPositionals: true,
    strict: true,
  });
  if (f.version) {
    out(pkg.version);
    return 0;
  }
  const [cmd, target, name] = positionals;
  if (f.help || !cmd) {
    out(HELP);
    return cmd || f.help ? 0 : 2;
  }

  // Every bundle names its provider, so parse first and load the keys it needs.
  const keyOpts = { region: f.region, worker: f.worker };
  const forEdit = async (path: string): Promise<BundleEditor> => {
    const text = await readText(localBundle(path));
    return BundleEditor.open(
      text,
      await providerFor(parseBundle(text), keyOpts)
    );
  };
  const forRead = async (
    spec: string
  ): Promise<{ bundle: Bundle; keys: KeyProvider }> => {
    const bundle = parseBundle(await readText(sourceFor(spec, f.region)));
    return { bundle, keys: await providerFor(bundle, keyOpts) };
  };
  const targets = [f["kms-key"], f.local, f.worker].filter(
    (v) => v !== undefined && v !== false
  );
  if (targets.length > 1) {
    throw new UsageError("use one of --kms-key, --local or --worker");
  }

  const minVersion =
    f["min-version"] !== undefined ? Number(f["min-version"]) : undefined;
  if (minVersion !== undefined && !Number.isSafeInteger(minVersion)) {
    throw new UsageError("--min-version takes a whole number");
  }
  const readOpts = {
    ...(f.env !== undefined ? { env: f.env } : {}),
    ...(minVersion !== undefined ? { minVersion } : {}),
  };

  switch (cmd) {
    case "init": {
      const path = need(target, "bundle file");
      if (await exists(path)) throw new UsageError(`${path} already exists`);
      const env = need(f.env, "--env");
      if (f.worker !== undefined) {
        const editor = await BundleEditor.create({
          env,
          keyId: CURRENT_WORKER_KEY,
          provider: workerKeys(f.worker),
        });
        await writeAtomic(path, await editor.seal());
        note(
          `Created ${path} for ${editor.env}, sealed by the Worker with key ${editor.keyId}`
        );
        note(
          `Give your app access with the entry \`keyseal policy ${path}\` prints`
        );
        return 0;
      }
      if (!f.local) {
        const editor = await BundleEditor.create({
          env,
          keyId: need(f["kms-key"], "--kms-key, --local or --worker"),
          provider: awsKeys(f.region),
        });
        await writeAtomic(path, await editor.seal());
        note(`Created ${path} for ${editor.env}, sealed with ${editor.keyId}`);
        return 0;
      }
      const local = await newLocalKey();
      const editor = await BundleEditor.create({
        env,
        keyId: local.keyId,
        provider: local.provider,
      });
      await writeAtomic(path, await editor.seal());
      note(
        `Created ${path} for ${editor.env}, sealed with local key ${local.keyId}`
      );
      noteLocalKey(local.path, path);
      return 0;
    }

    case "set":
    case "rotate": {
      const path = need(target, "bundle file");
      const secret = need(name, "secret name");
      const grace = parseDuration(
        f.grace ?? (cmd === "rotate" ? "24h" : "0"),
        "--grace"
      );
      const editor = await forEdit(path);
      const value = await readValue(secret, f.raw ?? false);
      if (!(await editor.set(secret, value, { grace }))) {
        note(`${secret} is unchanged`);
        return 0;
      }
      await writeAtomic(path, await editor.seal());
      const e = editor.entry(secret);
      const kept = e?.previous
        ? `, previous value readable until ${e.previous.expiresAt}`
        : "";
      note(
        `Set ${secret} (v${e?.v}) in ${path}, bundle version ${editor.version + 1}${kept}`
      );
      return 0;
    }

    case "import": {
      const path = need(target, "bundle file");
      const envFile = need(name, "dotenv file");
      // parseEnv never evaluates the file, unlike sourcing it in a shell.
      const parsed = parseEnv(await readFile(envFile, "utf8")) as Record<
        string,
        string | undefined
      >;
      const entries = Object.entries(parsed).filter(
        (e): e is [string, string] => typeof e[1] === "string"
      );
      if (entries.length === 0)
        throw new UsageError(`${envFile} has no values`);
      const bad = entries.map(([n]) => n).filter((n) => !isValidName(n));
      if (bad.length > 0) {
        throw new UsageError(`not valid secret names: ${bad.join(", ")}`);
      }
      const grace = parseDuration(f.grace ?? "0", "--grace");
      const editor = await forEdit(path);
      const changed: string[] = [];
      for (const [n, v] of entries) {
        if (await editor.set(n, v, { grace })) changed.push(n);
      }
      if (changed.length === 0) {
        note(
          `All ${entries.length} values in ${envFile} already match ${path}`
        );
        return 0;
      }
      await writeAtomic(path, await editor.seal());
      note(
        `Imported ${changed.length} of ${entries.length} values into ${path} (${changed.join(", ")}), bundle version ${editor.version + 1}`
      );
      return 0;
    }

    case "rm": {
      const path = need(target, "bundle file");
      const secret = need(name, "secret name");
      const editor = await forEdit(path);
      if (!editor.remove(secret))
        throw new KeysealError("not_found", `${secret} is not in ${path}`);
      await writeAtomic(path, await editor.seal());
      note(
        `Removed ${secret} from ${path}, bundle version ${editor.version + 1}`
      );
      return 0;
    }

    case "rekey": {
      const path = need(target, "bundle file");
      const editor = await forEdit(path);
      const kmsKey = f["kms-key"];
      const local = f.local ? await newLocalKey() : undefined;
      const fromKey = editor.keyId;
      if (local) {
        await editor.rekey(local.keyId, local.provider);
      } else if (kmsKey && editor.provider !== "aws-kms") {
        await editor.rekey(kmsKey, awsKeys(f.region));
      } else if (f.worker !== undefined && editor.provider !== "worker") {
        await editor.rekey(CURRENT_WORKER_KEY, workerKeys(f.worker));
      } else if (editor.provider === "worker") {
        // Whichever key the Worker writes with now, so rotating its key
        // and then rekeying moves every bundle over.
        await editor.rekey(CURRENT_WORKER_KEY);
      } else {
        await editor.rekey(kmsKey);
      }
      await writeAtomic(path, await editor.seal());

      if (editor.provider === "worker") {
        const moved =
          editor.keyId === fromKey ? "" : `, now under key ${editor.keyId}`;
        note(
          `Re-encrypted ${path} under a new data key from the Worker${moved}, epoch ${editor.epoch}`
        );
        note(
          `Once every app runs this bundle, add the minEpoch from \`keyseal policy ${path}\` to KEYSEAL_ACCESS to revoke epochs before ${editor.epoch}`
        );
      } else if (editor.provider === "aws-kms") {
        note(
          `Re-encrypted ${path} under a new data key from ${editor.keyId}, epoch ${editor.epoch}`
        );
        note(
          `Once every app runs this bundle, apply \`keyseal policy ${path}\` to revoke epochs before ${editor.epoch}`
        );
      } else if (local) {
        note(
          `Re-encrypted ${path} under new local key ${local.keyId}, epoch ${editor.epoch}`
        );
        noteLocalKey(local.path, path);
        note(
          "Before you publish it, add the new key to KEYSEAL_KEY next to the old one (space-separated), so running apps can open it; drop the old key once every app runs this bundle"
        );
      } else {
        note(
          `Re-encrypted ${path} under a new data key, same local key ${editor.keyId}, epoch ${editor.epoch}`
        );
        note(
          "Older copies still open with this key; to cut them off, rekey with --local for a new key"
        );
      }
      return 0;
    }

    case "key": {
      if (f.new) {
        if (target) throw new UsageError("key --new takes no bundle");
        // Only for the Worker: a bundle's own key comes from `init --local`.
        const key = generateLocalKey();
        process.stdout.write(process.stdout.isTTY ? `${key}\n` : key);
        note(
          "Keep an offline copy (a password manager works): Cloudflare never shows a secret again, and without it nobody can open bundles sealed with it"
        );
        return 0;
      }
      const b = parseBundle(
        await readText(sourceFor(need(target, "bundle"), f.region))
      );
      if (b.key.provider !== "local") {
        throw new UsageError(
          `this bundle is sealed with ${b.key.provider}; only local bundles have a key to print`
        );
      }
      const key = await findLocalKey(b.key.keyId);
      process.stdout.write(process.stdout.isTTY ? `${key}\n` : key);
      return 0;
    }

    case "policy": {
      const role = f.role ?? "app";
      if (role !== "app" && role !== "editor") {
        throw new UsageError("--role takes app or editor");
      }
      // Run this on your own copy: the policy trusts the bundle's fields.
      const b = parseBundle(
        await readText(sourceFor(need(target, "bundle"), f.region))
      );
      if (b.key.provider === "worker") {
        if (f.s3) throw new UsageError("--s3 is for AWS KMS bundles");
        out(JSON.stringify(workerAccess(b, { role }), null, 2));
        note(
          "Merge this into the Worker's KEYSEAL_ACCESS, with the token hash from `keyseal token`"
        );
        return 0;
      }
      if (b.key.provider !== "aws-kms") {
        throw new UsageError(
          `policy is for AWS KMS and Worker bundles; this one is sealed with ${b.key.provider}`
        );
      }
      out(
        JSON.stringify(
          bundlePolicy(b, { role, ...(f.s3 ? { s3: f.s3 } : {}) }),
          null,
          2
        )
      );
      return 0;
    }

    case "token": {
      if (target) throw new UsageError("token takes no arguments");
      const t = await newWorkerToken();
      process.stdout.write(process.stdout.isTTY ? `${t.token}\n` : t.token);
      note(`For KEYSEAL_ACCESS: "token": "${t.hash}"`);
      return 0;
    }

    case "ls": {
      const b = parseBundle(
        await readText(sourceFor(need(target, "bundle"), f.region))
      );
      out(
        `${b.env}, version ${b.version}, epoch ${b.key.epoch}, updated ${b.updatedAt} (not verified; run status to verify)`
      );
      const rows = [["NAME", "V", "ROTATED", "PREVIOUS"]];
      for (const n of sortedNames(b.secrets)) {
        const e = b.secrets.get(n);
        if (!e) continue;
        rows.push([
          n,
          String(e.v),
          `${e.rotatedAt} (${ago(e.rotatedAt)})`,
          e.previous ? `until ${e.previous.expiresAt}` : "",
        ]);
      }
      if (rows.length > 1) out(table(rows));
      return 0;
    }

    case "status": {
      const { bundle, keys } = await forRead(need(target, "bundle"));
      const { bundle: b, secrets } = await openBundle(bundle, keys, readOpts);
      out(`Verified: ${b.env}, version ${b.version}, updated ${b.updatedAt}`);
      out(`Key: ${b.key.provider} ${b.key.keyId}, epoch ${b.key.epoch}`);
      out(`Secrets: ${secrets.size}`);
      if (f["stale-since"] === undefined) return 0;
      const since = parseSince(f["stale-since"]);
      const stale = [...secrets].filter(
        ([, s]) => Date.parse(s.rotatedAt) < since
      );
      if (stale.length === 0) {
        out(`Every secret was rotated after ${new Date(since).toISOString()}`);
        return 0;
      }
      out(`\nNot rotated since ${new Date(since).toISOString()}:`);
      out(
        table(
          stale.map(([n, s]) => [n, `${s.rotatedAt} (${ago(s.rotatedAt)})`])
        )
      );
      return 1;
    }

    case "get": {
      const secret = need(name, "secret name");
      const { bundle, keys } = await forRead(need(target, "bundle"));
      const { secrets } = await openBundle(bundle, keys, readOpts);
      const s = secrets.get(secret);
      if (!s)
        throw new KeysealError("not_found", `${secret} is not in the bundle`);
      process.stdout.write(process.stdout.isTTY ? `${s.value}\n` : s.value);
      return 0;
    }

    case "export": {
      const { bundle, keys } = await forRead(need(target, "bundle"));
      const { secrets } = await openBundle(bundle, keys, readOpts);
      const env: Record<string, string> = Object.create(null);
      for (const [n, s] of secrets) env[n] = s.value;
      process.stdout.write(formatExport(env, f.format ?? "dotenv"));
      return 0;
    }

    case "run": {
      if (command.length === 0)
        throw new UsageError(
          "put the command after --, e.g. keyseal run secrets.ks.json -- node server.js"
        );
      const spec = need(target, "bundle");
      // One extra read to learn the provider before the runtime starts.
      const { keys } = await forRead(spec);
      return runCommand({
        source: sourceFor(spec, f.region),
        keys,
        command,
        watch: f.watch ?? false,
        pollMs: parseDuration(f.poll ?? "30s", "--poll"),
        stopTimeoutMs: parseDuration(
          f["stop-timeout"] ?? "10s",
          "--stop-timeout"
        ),
        ...readOpts,
      });
    }

    default:
      throw new UsageError(`unknown command "${cmd}"`);
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    if (err instanceof UsageError) {
      note(`keyseal: ${err.message}\nRun keyseal --help for usage.`);
      process.exitCode = 2;
    } else if (err instanceof KeysealError) {
      note(`keyseal: ${err.message} (${err.code})`);
      process.exitCode = 1;
    } else if (
      err instanceof TypeError &&
      "code" in err &&
      String(err.code).startsWith("ERR_PARSE_ARGS")
    ) {
      note(`keyseal: ${err.message}\nRun keyseal --help for usage.`);
      process.exitCode = 2;
    } else {
      note(`keyseal: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
  }
);
