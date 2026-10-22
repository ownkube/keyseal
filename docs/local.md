# Local keys (no AWS account)

A local key replaces KMS with a 32-byte key you generate and keep. Nothing
else changes: same bundles, same commands, same rotation by polling.

> **Read this first.** Your app gets a local key from the `KEYSEAL_KEY` env
> var, which lives in your platform's env store. If that store leaks, the
> attacker has the key, and with the bundle they can
> read every value. Nothing records that they did. See the
> [threat model](../spec/THREAT_MODEL.md#local-mode-what-it-protects-and-what-it-doesnt).

Local keys are a good fit for getting started, development and staging,
and projects without an AWS account. Move production to KMS when an env
store breach would hurt: `keyseal rekey <file> --kms-key <key>`.

## Set up

```sh
npx keyseal init secrets/production.ks.json --env production --local
npx keyseal import secrets/production.ks.json .env.production
git add secrets/production.ks.json
```

`init --local` saves the key in `~/.config/keyseal/keys/<key id>.key`
(mode `0600`) and never prints it. **Back it up now**, for example in a
password manager: if every copy is lost, nobody can open the bundle.
Anyone else who edits the bundle needs the same key on their machine, in
the same directory or in `KEYSEAL_KEY`.

## Give the app the key

`keyseal key <bundle>` prints the key for that bundle. Pipe it straight
into your platform's CLI so it never lands in your terminal, shell history
or a file:

```sh
npx keyseal key secrets/production.ks.json | vercel env add KEYSEAL_KEY production
npx keyseal key secrets/production.ks.json | gh secret set KEYSEAL_KEY
```

Or run it in a terminal and paste the output into the platform's
dashboard. Then start the app as usual:

```sh
npx keyseal run secrets/production.ks.json --env production -- node server.js
```

`run` removes `KEYSEAL_KEY` from the command's environment, so the app and
its dependencies never see it. From code, use `localKey()`, which reads
`KEYSEAL_KEY`:

```ts
import { createKeyseal, localKey } from "@ownkube/keyseal";

export const secrets = await createKeyseal({
  source: "secrets/production.ks.json",
  keys: localKey(),
  env: "production",
});
```

Use a different key per environment, so a leaked staging key reads only
staging.

## Rotate values

The same as with KMS: `keyseal rotate`, commit or publish, and apps that
poll pick it up. See [rotation](rotation.md). A plain `rekey` keeps the key
and only replaces the data key.

## Change the key

Do this when someone who had the key leaves, or on a schedule.

1. `npx keyseal rekey secrets/production.ks.json --local` creates a new key
   and re-encrypts the bundle under it.
2. Set `KEYSEAL_KEY` on the platform to the old and new keys together,
   separated by a space or newline. Readers use whichever one the bundle
   names, so apps keep working before and after the new bundle arrives.
3. Publish the new bundle and wait for apps to pick it up.
4. Set `KEYSEAL_KEY` to the new key alone.

Old bundles in git history still open with the old key. Changing the key
protects what you publish from now on, not what was already out.

## If the key leaked

Assume every value in every bundle sealed with that key was read, including
copies in git history.

1. Rotate every value at its provider (Stripe, the database, and so on).
2. `keyseal rekey <file> --local`, then `keyseal rotate` each value in the
   new bundle.
3. Set `KEYSEAL_KEY` on the platform to the new key alone, and publish.

Unlike KMS, there's no log to tell you whether the key was used, and no
credential to switch off while you work. That's the trade.
