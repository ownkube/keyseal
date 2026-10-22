# Incidents and hardening

You don't need anything on this page to use keyseal. It covers what to do
when something goes wrong, and the extra protections you can turn on.

- [Incident playbook](#incident-playbook): your platform's env store leaked.
- [Revoking old bundles](#revoking-old-bundles): make every older copy of a
  bundle unreadable, enforced by KMS.
- [Rollback protection](#rollback-protection): stop apps loading an older
  bundle.

## Incident playbook

Your platform reports that its env var store was breached.

For bundles sealed with a local key, the store held the key, so skip this
playbook: treat every value as read and follow
[If the key leaked](local.md#if-the-key-leaked).

For Worker bundles, apps on OIDC stored nothing usable. For a token app,
search Workers Logs for its client name from addresses that aren't your
platform's. If there are any, or the token wasn't pinned with `ips`,
remove the client from `KEYSEAL_ACCESS` and deploy the Worker, add a new
token, then rotate the values at their providers and publish. After a
`rekey`, set [`minEpoch`](cloudflare.md#revoke-old-bundles) to cut off older
copies.

The steps below are for KMS bundles.

1. **Check who decrypted.** Run the [CloudTrail
   query](aws.md#checking-who-decrypted) for each environment's key. Every
   decrypt of a bundle shows up there with the caller and IP.
2. **Find what's still in plaintext.** Anything you never moved into a
   bundle is exposed. Rotate those first.
3. **Decide what the attacker could decrypt**, based on how the app signs
   in to AWS:
   - **Workload identity or OIDC:** the platform's store held no AWS
     secret. Bundle values were not exposed by this breach.
   - **A static key pinned with `aws:SourceIp`:** the key is useless away
     from your platform's addresses. CloudTrail should show only those
     addresses. Swap the key when convenient: IAM users can have two keys,
     so create the new one, set it on the platform, then deactivate the old
     one.
   - **A static key without an IP pin, and CloudTrail shows decrypts from
     addresses that aren't your platform:** treat every value in that
     environment as leaked. Deactivate the key in IAM now, because while it
     works it can also read any new bundle you publish. Running processes
     keep serving the values they already have. Then rotate every value at
     its provider, publish the new bundle, and set a new access key on the
     platform so processes can pick it up (on most platforms that takes a
     restart).
   - **A static key without an IP pin, and CloudTrail shows nothing
     unexpected:** rotate the values you're worried about, publish, wait for
     apps to pick them up, then swap the access key as above.
4. **Rotate and publish** with [`keyseal rotate`](rotation.md#rotating-a-value).
   Apps that poll pick the new values up without a deploy.
5. **Cut off the pre-incident bundles.** If values may have been read,
   [revoke the old bundles](#revoking-old-bundles), so KMS refuses them
   everywhere. Until then, [raise the minimum version](#rollback-protection).
6. **Confirm nothing was missed:**

   ```sh
   npx keyseal status secrets/production.ks.json --stale-since 2026-03-01
   ```

   This lists every secret not rotated since that date and exits 1 if there
   are any.

## Revoking old bundles

Every old copy of a bundle (git history, old S3 versions, a stale copy
baked into an image, one an attacker serves from a URL they control) opens
with the same data key as the current one. A `rekey` plus one IAM statement
changes that.

Each bundle has a key epoch: 1 when created, plus 1 on every `rekey`. The
epoch is part of the KMS encryption context and covered by the bundle MAC,
so IAM can refuse every data key from before the rekey, and editing the
epoch in an old file only breaks it.

```sh
npx keyseal rekey secrets/production.ks.json        # epoch 1 -> 2
npx keyseal rekey secrets/production.ks.json --kms-key alias/keyseal-production-2
```

Then, in this order:

1. **Commit and publish** the rekeyed bundle.
2. **Wait until every app runs it.** Polling apps pick it up on their next
   poll (one `Decrypt` each). Apps with a baked-in bundle need a deploy.
3. **Apply the new policy** to the app's role or user:

   ```sh
   npx keyseal policy secrets/production.ks.json --s3 s3://acme-keyseal/production.ks.json
   ```

   It now ends with a statement like this one:

   ```json
   {
     "Sid": "KeysealRevokedEpochs",
     "Effect": "Deny",
     "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
     "Resource": "*",
     "Condition": {
       "StringEquals": {
         "kms:EncryptionContext:keyseal:bundle": "Xq3m0yJw6Zr1k2v9Qp7tLg",
         "kms:EncryptionContext:keyseal:epoch": ["1"]
       }
     }
   }
   ```

   `Resource` is `*` because older epochs may have used a different KMS
   key. It's an IAM change, so it takes effect without a deploy.

Applying the Deny too early is safe for running processes, which keep the
data key they hold, but a process that restarts on the old bundle fails
with `key_unavailable`.

Revoking stops anyone opening old bundles *from now on*. It can't undo a
decrypt that already happened, so still rotate values at their providers if
they might have been read.

A local key has no Deny: anyone with the key opens every bundle ever sealed
with it. `rekey --local` moves new bundles to a new key, which is the only
way to cut old copies off ([change the key](local.md#change-the-key)).

## Rollback protection

Someone with write access to wherever the app reads its bundle could serve
an older, validly sealed copy, for example to bring back a value you
rotated.

A running process refuses any bundle older than the one it has, and refuses
a bundle with a different id. A new process has nothing to compare against.
Two ways to cover that:

- **Revoke the old bundles** as above. KMS enforces it, so it needs no app
  config. It covers everything from before the last rekey.
- **Pin a minimum version** in the app's config. It covers every version,
  including ones between two rekeys:

  ```sh
  npx keyseal ls secrets/production.ks.json | head -1   # "production, version 14, epoch 2, ..."
  ```

  Set `KEYSEAL_MIN_VERSION=14` (library) or `--min-version 14` (CLI).
  Changing that setting on the platform might need a deploy, but running
  processes are already protected, so it can wait until deploys work again.

Whichever you use, keep write access to the bucket or URL for yourself and
your publishing CI job only.
