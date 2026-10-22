# Reference

## CLI

```
keyseal <command> <bundle> [args] [flags]
```

AWS credentials come from the standard AWS SDK chain (`AWS_PROFILE`, SSO,
environment variables, a role). The KMS region comes from the key ARN stored
in the bundle. `--region` (or `AWS_REGION`) is needed only for `init` with a
key alias and for S3 bundles.

Bundles sealed with a [local key](local.md) make no AWS calls. The CLI
reads the key from `KEYSEAL_KEY`, then from the file `init --local` saved
(see [Environment variables](#environment-variables)).

### Write commands

These edit a **local file**. To change a published bundle, edit the file in
your repo and publish it again.

| Command | What it does | AWS calls |
|---|---|---|
| `init <file> --env <env> --kms-key <key>` | Create an empty bundle. `<key>` is a key ARN, key id or alias. Fails if the file exists. | `GenerateDataKey` |
| `init <file> --env <env> --local` | Create an empty bundle under a new [local key](local.md), saved in the key directory. Never prints the key. | None |
| `init <file> --env <env> --worker <url>` | Create an empty bundle sealed by your [keyseal Worker](cloudflare.md), with an editor token in `KEYSEAL_WORKER_TOKEN`. | None (one Worker call) |
| `set <file> <NAME> [--grace 0]` | Set one value, read from a hidden prompt or piped stdin. | `Decrypt` |
| `rotate <file> <NAME> [--grace 24h]` | Same as `set`, keeping the old value readable for the grace window. | `Decrypt` |
| `import <file> <dotenv-file> [--grace 0]` | Set every value in a `.env` file in one write. Prints names only. Fails before writing if any name is invalid. | `Decrypt` |
| `rm <file> <NAME>` | Remove a secret. | `Decrypt` |
| `rekey <file> [--kms-key <key> \| --local \| --worker <url>]` | Re-encrypt everything under a new data key and the next key epoch, optionally under a different KMS key, a new local key or a Worker. Each flag also moves a bundle to that provider. A Worker bundle always moves to the Worker's current key. See [Revoking old bundles](hardening.md#revoking-old-bundles). | `Decrypt`, `GenerateDataKey` (KMS only) |

Every write increments the bundle version. A `set`, `rotate` or `import`
that changes no values leaves the file alone.

Values never come from command-line arguments, which end up in shell
history and process listings. Piped input loses one trailing newline unless
you pass `--raw`.

### Read commands

`<bundle>` is a file path, an `https://` URL or `s3://bucket/key`.

| Command | What it does | AWS calls |
|---|---|---|
| `key <bundle>` | Print the local key the bundle is sealed with, to set as `KEYSEAL_KEY` on your platform. No trailing newline when piped. Pipe it straight into the platform's CLI. | None |
| `policy <file> [--role app\|editor] [--s3 s3://bucket/key]` | Print the IAM policy for a KMS bundle: the app's (default) or an editor's, with S3 access when `--s3` is given, and a Deny for every older key epoch. For a Worker bundle, print the `KEYSEAL_ACCESS` entry instead, with `minEpoch` for older epochs. Run it on your own copy. | None |
| `key --new` | Print a new key for the Worker's `KEYSEAL_KEY` secret. Save it offline, then paste it into `wrangler secret put KEYSEAL_KEY`. | None |
| `token` | Print a new Worker token on stdout and its `sha256:` hash for `KEYSEAL_ACCESS` on stderr. | None |
| `ls <bundle>` | Version, key epoch, names and rotation times. Doesn't decrypt or verify. | None (S3 `GetObject` for S3 bundles) |
| `status <bundle>` | Decrypt and verify everything, print a summary. | `Decrypt` |
| `status <bundle> --stale-since <when>` | Also list secrets not rotated since `<when>` (a date like `2026-03-01` or a duration like `36h`). Exits 1 if any. | `Decrypt` |
| `get <bundle> <NAME>` | Print one value. No trailing newline when piped. | `Decrypt` |
| `export <bundle> [--format dotenv\|shell\|json]` | Print every value. | `Decrypt` |
| `run <bundle> [--watch] [--poll 30s] [--stop-timeout 10s] -- <command...>` | Start a command with the secrets as environment variables. With `--watch`, poll and restart the command when values change. | `Decrypt` once |

`get`, `export`, `key` and `token` print secrets. Prefer `run` or the library.

### Flags

| Flag | Applies to | Meaning |
|---|---|---|
| `--env <env>` | read commands | Refuse a bundle for any other environment. Always set it in production. |
| `--min-version <n>` | read commands | Refuse a bundle older than version `n`. |
| `--region <region>` | all | AWS region when it can't come from the key ARN. |
| `--local` | `init`, `rekey` | Use a new local key instead of KMS. |
| `--worker <url>` | all | Your keyseal Worker. Default `KEYSEAL_WORKER_URL`. Never read from the bundle. |
| `--grace <duration>` | `set`, `rotate`, `import` | How long the replaced value stays readable. `0` for none. |
| `--raw` | `set`, `rotate` | Keep a trailing newline from piped input. |
| `--role app\|editor` | `policy` | Which policy to print. Default `app`. |
| `--s3 s3://bucket/key` | `policy` | Add read access (write too, for editors) to the published bundle. |
| `--watch` | `run` | Restart the command when values change. |
| `--poll <duration>` | `run --watch` | Poll interval, at least `1s`. Default `30s`. |
| `--stop-timeout <duration>` | `run --watch` | Time between `SIGTERM` and `SIGKILL` on restart. Default `10s`. |

Durations are a whole number with a unit: `500ms`, `30s`, `15m`, `24h`, `7d`.

### Environment variables

| Variable | Meaning |
|---|---|
| `KEYSEAL_KEY` | Local keys, separated by spaces, commas or newlines. A reader uses the one the bundle names, so during a key change you can set the old and new key together. |
| `KEYSEAL_KEY_DIR` | Where the CLI saves and looks up local keys. Default `$XDG_CONFIG_HOME/keyseal/keys`, else `~/.config/keyseal/keys`. One file per key, `<key id>.key`, mode `0600`. |
| `KEYSEAL_WORKER_URL` | The Worker's base URL, for Worker bundles. |
| `KEYSEAL_WORKER_TOKEN` | The bearer token for the Worker. |
| `AWS_REGION`, `AWS_PROFILE`, ... | The standard AWS SDK settings, for KMS bundles and S3. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | A keyseal error (the message ends with its code, e.g. `(env_mismatch)`), an AWS error, or `status --stale-since` found stale secrets. |
| `2` | Bad usage: unknown command, missing argument, bad flag. |
| other | `run` exits with the command's own exit code, `127` if it couldn't start, or `128 + signal` if it was killed. |

### `run` details

- Bundle values override variables with the same name already in the
  environment. `KEYSEAL_KEY` and `KEYSEAL_WORKER_TOKEN` are removed from
  the command's environment.
- `SIGTERM` and `SIGHUP` are forwarded to the command, and so is `SIGINT`
  when there's no terminal (a terminal already delivers Ctrl-C to it).
- With `--watch`, a failed poll keeps the current values and logs to
  stderr. A rekey, which changes no values, doesn't restart the command.

## Library

```ts
import { createKeyseal } from "@ownkube/keyseal";
import { awsKms } from "@ownkube/keyseal/aws";
import { s3 } from "@ownkube/keyseal/s3";
```

The main entry point has no AWS dependency. The AWS SDK is loaded only when
you import `@ownkube/keyseal/aws` or `@ownkube/keyseal/s3`.

### `createKeyseal(options): Promise<Keyseal>`

Loads and verifies the bundle, then serves values from memory.

| Option | Type | Default | Meaning |
|---|---|---|---|
| `source` | `Source \| string` | required | A source, a file path or an `https://` URL. For S3, pass `s3(...)`. |
| `keys` | `KeyProvider` | required | `awsKms()` in production, `testKeys()` in tests. |
| `env` | `string` | none | Refuse a bundle for any other environment. Recommended. |
| `minVersion` | `number` | none | Refuse bundles older than this, including on the first load. |
| `poll` | `number \| false` | `30000` (off for `inline`) | Poll interval in ms, at least 1000. |
| `inject` | `boolean \| string[]` | `false` | Also write every value, or the named ones, into `process.env`. Removed secrets are deleted from it. |

It rejects with a `KeysealError` if the first load fails. After that, a
failed poll emits `error` and keeps the current values.

### `Keyseal`

| Member | Meaning |
|---|---|
| `get(name)` | The current value. Throws `not_found` for an unknown name. |
| `has(name)` | Whether the secret exists. |
| `previous(name)` | The value replaced by the last rotation, while its grace window is open. |
| `names()` | Every secret name. |
| `toEnv()` | Every value as an object, e.g. for a child process. |
| `redact(text)` | Replace every value of 8 or more characters in `text` with `[redacted:NAME]`. |
| `refresh()` | Check the source now. Resolves `true` if a new bundle was loaded. |
| `on("rotated", fn)` | `fn({ version, changed, added, removed })` after a new bundle loads. Returns an unsubscribe function. |
| `on("error", fn)` | `fn(err)` when a poll fails. |
| `close()` | Stop polling and drop listeners. |
| `id`, `env`, `version`, `updatedAt` | About the loaded bundle. |

Logging the client (`console.log`, `JSON.stringify`) prints names and the
version, never values. The polling timer doesn't keep the process alive.

### Sources

| Function | From | Notes |
|---|---|---|
| `file(path)` | `@ownkube/keyseal` | A file on disk. |
| `url(href, { headers?, allowInsecure?, fetch? })` | `@ownkube/keyseal` | HTTPS only (plain HTTP for localhost or with `allowInsecure`). Uses `If-None-Match`, so unchanged polls are cheap. |
| `inline(text)` | `@ownkube/keyseal` | A bundle already in memory. Never polled. |
| `s3("s3://bucket/key")` or `s3({ bucket, key, region?, client?, clientConfig? })` | `@ownkube/keyseal/s3` | Uses `GetObject` with `If-None-Match`. |

A source is any object with `description` and
`read(etag?) => Promise<{ body, etag? } | null>`, so you can write your own.

### Key providers

`awsKms({ client?, region?, clientConfig? })` from `@ownkube/keyseal/aws`.
Pass `clientConfig: { credentials }` to use credentials other than the
default chain, for example from `@aws-sdk/credential-providers`. Every call
sends the bundle id and environment as KMS encryption context and pins the
key from the bundle.

`localKey({ keys? })` from `@ownkube/keyseal`. `keys` is one key or an
array, and defaults to `KEYSEAL_KEY`. A malformed key fails with
`invalid_argument` without echoing it. `generateLocalKey()` makes a new
key, and `localKeyId(key)` returns the id a bundle stores for it.

`worker({ url?, token?, fetch?, timeoutMs? })` from `@ownkube/keyseal`.
`url` defaults to `KEYSEAL_WORKER_URL` and must be https (http only for
localhost). `token` is a string or a function returning one, for a platform
OIDC token fetched fresh, and defaults to `KEYSEAL_WORKER_TOKEN`. Redirects
are refused. The Worker itself is the default export of
`@ownkube/keyseal/cloudflare`; `createWorker({ fetch?, now?, log? })`
builds one with injected dependencies.

A provider is any object implementing `KeyProvider` (`name`,
`generateDataKey`, `decryptDataKey`). `aws-kms`, `local` and `worker` are
defined today.

### Editing from code

```ts
import { BundleEditor } from "@ownkube/keyseal";

const editor = await BundleEditor.open(text, awsKms());
await editor.set("API_KEY", value, { grace: 3_600_000 });
editor.remove("OLD_KEY");
const next = await editor.seal(); // new bundle text, version + 1
```

`BundleEditor.create({ env, keyId, provider })` makes a new bundle.
`editor.rekey(keyId?)` switches to a new data key. `openBundle(text, keys,
{ env?, minVersion? })` opens a bundle once without a client.

### Errors

Every failure is a `KeysealError` with a `code`. Check it with
`isKeysealError(err, "env_mismatch")`.

| Code | Meaning |
|---|---|
| `invalid_format` | Not a valid bundle. |
| `unsupported_format` | A bundle format version this release doesn't know. |
| `env_mismatch` | The bundle is for a different environment than the pinned one. |
| `provider_mismatch` | The bundle names a key provider you didn't pass (e.g. a test bundle in production). |
| `key_unavailable` | KMS refused or failed to unwrap the data key: missing permission, wrong encryption context, throttling, disabled key. The cause is attached. |
| `mac_mismatch` | The bundle was modified, or doesn't match its key. |
| `decrypt_failed` | A value didn't decrypt despite a valid MAC: a writer bug, or an edit by someone holding the data key. |
| `rollback` | The bundle is older than the loaded one or the minimum version. |
| `not_found` | No secret with that name. |
| `bundle_changed` | The source started serving a different bundle. Restart to accept it. |
| `source_unavailable` | The bundle couldn't be fetched. |
| `invalid_argument` | A bad name, environment or option. |

The bundle format itself is specified in [spec/FORMAT.md](../spec/FORMAT.md).
