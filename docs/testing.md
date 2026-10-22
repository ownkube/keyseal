# Testing

This page has three parts: unit tests for code that uses keyseal (no AWS
needed), checks that a real setup works, and tests for keyseal itself.

## Unit tests for your app

`@ownkube/keyseal/testing` builds real bundles with a fixed test key, so
your tests run the same code path as production with no KMS and no network.

| Helper | What it does |
|---|---|
| `testKeys(dataKey?)` | A key provider that hands back a fixed 32-byte data key. Pass it as `keys`. |
| `sealTestBundle(secrets, { env?, keys? })` | Seals a bundle holding `secrets`. `env` defaults to `"test"`. |
| `testSource(bundle)` | A source you can change from the test with `publish(newBundle)`. Also exposes `body` (current bundle) and `reads` (poll count). |

Never use these for real secrets. The test key protects nothing, and
production readers refuse the `test` provider unless you pass it.

### Give your code a `Keyseal`, don't import a global

Code that receives the client as a parameter is easy to test:

```ts
// src/billing.ts
import type { Keyseal } from "@ownkube/keyseal";

export function createBilling(secrets: Keyseal) {
  return {
    authHeader: () => `Bearer ${secrets.get("STRIPE_SECRET_KEY")}`,
  };
}
```

```ts
// src/main.ts
import { createKeyseal } from "@ownkube/keyseal";
import { awsKms } from "@ownkube/keyseal/aws";
import { s3 } from "@ownkube/keyseal/s3";
import { createBilling } from "./billing.ts";

const secrets = await createKeyseal({
  source: s3("s3://acme-keyseal/production.ks.json"),
  keys: awsKms(),
  env: "production",
});
const billing = createBilling(secrets);
```

### A basic test

This uses `node:test`. Vitest and Jest work the same way.

```ts
import assert from "node:assert/strict";
import { test } from "node:test";
import { createKeyseal } from "@ownkube/keyseal";
import { sealTestBundle, testKeys, testSource } from "@ownkube/keyseal/testing";
import { createBilling } from "../src/billing.ts";

test("sends the Stripe key", async () => {
  const keys = testKeys();
  const secrets = await createKeyseal({
    source: testSource(await sealTestBundle({ STRIPE_SECRET_KEY: "sk_test_1" }, { keys })),
    keys,
    env: "test",
    poll: false,
  });
  assert.equal(createBilling(secrets).authHeader(), "Bearer sk_test_1");
  secrets.close();
});
```

Pass `poll: false` in tests so no timer runs, and call `close()` when done.

### Testing rotation

Publish a new bundle to the test source and call `refresh()`, which is what
a poll does:

```ts
import { BundleEditor, createKeyseal } from "@ownkube/keyseal";

test("picks up a rotated key", async () => {
  const keys = testKeys();
  const source = testSource(await sealTestBundle({ STRIPE_KEY: "sk_test_old" }, { keys }));
  const secrets = await createKeyseal({ source, keys, env: "test", poll: false });

  const rotated: string[][] = [];
  secrets.on("rotated", (e) => rotated.push(e.changed));

  const editor = await BundleEditor.open(source.body, keys);
  await editor.set("STRIPE_KEY", "sk_test_new");
  source.publish(await editor.seal());

  await secrets.refresh();
  assert.equal(secrets.get("STRIPE_KEY"), "sk_test_new");
  assert.deepEqual(rotated, [["STRIPE_KEY"]]);
  secrets.close();
});
```

`editor.set(name, value, { grace: 3_600_000 })` keeps the old value for an
hour, so you can test code that falls back to `secrets.previous(name)`.

### Apps that use `keyseal run`

Nothing to do. The app reads ordinary environment variables, so tests set
them the way they always have.

## Checking a real setup

Run these after setup, and again after changing IAM, the bucket or the key.

### The app's identity can open the bundle

Run `status` as the app's role, not as yourself. You probably have more
access than the app does.

```sh
AWS_PROFILE=app-production npx keyseal status s3://acme-keyseal/production.ks.json --env production
```

Expected:

```
Verified: production, version 14, updated 2026-10-22T10:00:00Z
Key: aws-kms arn:aws:kms:us-east-1:111122223333:key/...
Secrets: 12
```

If you don't have a profile for the role, run the same command once from
inside the app's environment (a one-off task, `kubectl exec`, or a shell on
the platform).

### The app's identity can't edit

The app should have `kms:Decrypt` only. This must fail with an access error:

```sh
AWS_PROFILE=app-production aws kms generate-data-key \
  --key-id alias/keyseal-production --key-spec AES_256 \
  --encryption-context keyseal:env=production --query KeyId
```

### The environment pin works

Opening the production bundle as staging must fail:

```sh
npx keyseal status secrets/production.ks.json --env staging   # env_mismatch, exit 1
```

### A rotation drill

Do this once before you need it, so you know how long rotation takes.

1. Add a canary secret that nothing uses:

   ```sh
   openssl rand -hex 16 | npx keyseal set secrets/production.ks.json KEYSEAL_CANARY
   ```

2. Commit, publish and wait for the app to start with it.
3. Rotate it, and note the time:

   ```sh
   openssl rand -hex 16 | npx keyseal rotate secrets/production.ks.json KEYSEAL_CANARY
   ```

4. Commit and publish.
5. Watch the app's logs for the `rotated` event (library) or
   `keyseal: bundle version N changed KEYSEAL_CANARY; restarting` (`keyseal
   run --watch`). The gap between step 3 and that line is your rotation
   time.
6. Run the [CloudTrail query](aws.md#checking-who-decrypted) and check that
   every decrypt came from an identity you recognise.

## Testing keyseal itself

From `ts/`:

```sh
pnpm install
pnpm check      # format, lint and type check (Vite+)
pnpm test       # unit tests and the conformance vectors
pnpm build      # bundle to dist/
pnpm fix        # apply formatting and lint fixes
```

`spec/testvectors/v1.json` holds bundles and the result of opening each
one. Every implementation must produce exactly those results. The vectors
are generated deterministically by `pnpm vectors`. A test fails if the
committed file drifts from the generator, so regenerate and commit it when
you change the format on purpose.
