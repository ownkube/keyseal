# Setup runbook for AI coding agents

This page is written for an AI coding agent (Claude Code, Codex, Cursor and
similar) asked to "set up keyseal" in a Node app. Humans can follow it too.
Work through the steps in order. Each one has a command, a check that must
pass before you continue, and the points where you must stop and ask the
user.

The background for each step is in [getting-started.md](getting-started.md)
and [rotation.md](rotation.md).

## Ground rules

These are not optional. Secret values must never enter your context, your
logs or the conversation.

1. **Never print a value.** Don't run `cat`, `less`, `head`, `grep` without
   `-o`, `keyseal get`, `keyseal export`, `env`, `printenv`, or a platform
   command that lists variables with values, on anything that holds secrets.
   The same goes for local keys: run `keyseal key` only piped straight into
   a platform CLI (`npx keyseal key <bundle> | vercel env add KEYSEAL_KEY
   production`), and never read `~/.config/keyseal/keys`. For a Worker,
   run `keyseal token` only piped into a platform CLI, never print
   `KEYSEAL_WORKER_TOKEN`, and never run `keyseal key --new`: the user
   generates the Worker's key and stores it themselves
   ([cloudflare.md](cloudflare.md)).
2. **Never ask the user to paste a value into the chat.** Values move from a
   file to the bundle with `keyseal import`, or the user types them into a
   hidden prompt with `keyseal set`.
3. **Never put a value in a command line**, a script, a commit, a test
   fixture or a file other than the bundle.
4. **List names only.** To see which variables a `.env` file defines:

   ```sh
   grep -oE '^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' .env.production \
     | sed -E 's/^[[:space:]]*(export[[:space:]]+)?//; s/[[:space:]]*=$//'
   ```

   After values are in a bundle, use `npx keyseal ls <bundle>`.
5. **Don't widen permissions to get past an error.** If AWS says
   `AccessDenied`, stop and report what was denied.
6. **Don't commit or push** unless the user's instructions for this repo
   allow it.

## Stop points

Stop and ask the user, then wait for an answer, when you reach any of
these:

| ID | When | Ask |
|---|---|---|
| **S1** | Before creating any AWS resource | Confirm the AWS account id and ARN printed in step 1, the region, the environment names, and (if used) the bucket name. Mention that each KMS key costs $1 a month. |
| **S2** | When you need values that aren't in a local file | Ask the user to put them in a gitignored file, or to run `keyseal set` themselves (step 5). |
| **S3** | Before creating an IAM user or access key | Static keys are the fallback for platforms without workload identity. Confirm the platform has no OIDC or role option, and whether it has fixed egress IPs to pin. |
| **S4** | Before deleting any plaintext copy | Local `.env` files and the platform's variables. The user deletes platform variables after confirming the app runs. |
| **S5** | On any error you can't explain from this page | Report the command, the error message and the code in parentheses. |

## Step 1: Preflight

```sh
node --version
aws --version
aws sts get-caller-identity
git status --short
```

**Check:** Node is 22.12 or later. The AWS CLI works and prints an account
and ARN. Then **stop at S1** and confirm the account, region and
environments with the user.

**Inventory:** find the secrets the app uses without reading values:

```sh
grep -rhoE 'process\.env\.[A-Z_][A-Z0-9_]*' src | sort -u
ls -a | grep -E '^\.env'
```

Use the name listing from ground rule 4 for each `.env*` file. Record the
list of names for each environment. You'll compare against it in step 5.

## Step 2: Install

```sh
npm install --save-exact @ownkube/keyseal
npx keyseal --version
```

Use the project's package manager (`pnpm add --save-exact`, `yarn add
--exact`) if it isn't npm.

**Check:** the version prints, and `package.json` lists `@ownkube/keyseal`
at an exact version (no `^`).

## Step 3: Create a KMS key for each environment

Only after S1. Replace `production` and the region for each environment.

```sh
REGION=us-east-1
ENV=production
KEY_ARN=$(aws kms create-key --region "$REGION" \
  --description "keyseal $ENV" --query KeyMetadata.Arn --output text)
aws kms create-alias --region "$REGION" \
  --alias-name "alias/keyseal-$ENV" --target-key-id "$KEY_ARN"
aws kms enable-key-rotation --region "$REGION" --key-id "$KEY_ARN"
echo "$KEY_ARN"
```

If `alias/keyseal-$ENV` already exists, don't create another key. Reuse it
and tell the user.

**Check:**

```sh
aws kms describe-key --region "$REGION" --key-id "alias/keyseal-$ENV" \
  --query 'KeyMetadata.[Arn,KeyState]' --output text
```

prints the ARN and `Enabled`. Record the ARN for each environment.

## Step 4: Create the bundles

```sh
npx keyseal init "secrets/$ENV.ks.json" --env "$ENV" \
  --kms-key "alias/keyseal-$ENV" --region "$REGION"
```

**Check:** `npx keyseal ls "secrets/$ENV.ks.json"` prints `<env>, version
1` and no secrets.

## Step 5: Add the values

**If the values are in a local dotenv file** (e.g. `.env.production`), you
can import it. The values go from the file into the bundle and nothing is
printed:

```sh
npx keyseal import "secrets/$ENV.ks.json" ".env.$ENV"
```

If import fails with `not valid secret names`, the file has names keyseal
can't store. Report them to the user. Don't edit the file to work around it.

**If the values are only on the platform or in a password manager,** stop
at S2. Either the user exports them to a gitignored file for you to import
(make sure `git check-ignore <file>` prints the file name first), or the
user runs this for each secret in their own terminal (in Claude Code, by
typing `!` before the command):

```sh
npx keyseal set secrets/production.ks.json STRIPE_SECRET_KEY
```

It prompts for the value without echoing it.

**Check:**

```sh
npx keyseal ls "secrets/$ENV.ks.json"
npx keyseal status "secrets/$ENV.ks.json" --env "$ENV"
```

`ls` lists exactly the names from your step 1 inventory, and `status`
prints `Verified`. If a name is missing, report it. Don't invent values.

## Step 6: Keep plaintext out of git, then commit the bundles

```sh
git check-ignore -q .env.production && echo ignored
git add secrets/*.ks.json
git status --short
```

**Check:** every `.env*` file holding values is ignored. If not, add it to
`.gitignore` before anything else. Only the bundles are staged. Commit if
your instructions allow it (ground rule 6).

## Step 7: Load secrets in the app

Ask the user which way they want it, or choose `keyseal run` if the app
isn't TypeScript or JavaScript or they want no code changes.

**`keyseal run`:** change the start command. For `package.json`:

```json
"start": "keyseal run secrets/production.ks.json --env production -- node server.js"
```

For a Dockerfile, use `node_modules/.bin/keyseal` in `CMD` the same way.
Keep the original command after `--` exactly as it was.

**The library:** create one client at startup and pass it where secrets
are used. See [getting-started.md](getting-started.md#5-load-secrets-in-the-app)
and, for testability, [testing.md](testing.md#give-your-code-a-keyseal-dont-import-a-global).
Replace each `process.env.NAME` for a secret with `secrets.get("NAME")`,
read at the point of use.

**Check without printing values:**

```sh
npx keyseal run secrets/development.ks.json --env development -- \
  node -e 'const missing = process.argv.slice(1).filter((n) => !process.env[n]); console.log(missing.length ? "missing: " + missing.join(", ") : "all present"); process.exit(missing.length ? 1 : 0)' \
  STRIPE_SECRET_KEY DATABASE_URL
```

with the names from your inventory. It prints names, never values. Then run
the project's own tests.

## Step 8 (recommended): Rotation without a deploy

Ask the user whether they want this. It needs an S3 bucket (stop at S1 for
the name) and a publish step. Follow [rotation.md](rotation.md) sections 1
to 3: create the bucket, add the GitHub Actions workflow and its OIDC role,
and point the app at `s3://<bucket>/<env>.ks.json` with `--watch` or the
`s3()` source.

**Check:**

```sh
aws s3 cp "secrets/$ENV.ks.json" "s3://$BUCKET/$ENV.ks.json" --content-type application/json
npx keyseal ls "s3://$BUCKET/$ENV.ks.json" --region "$REGION"
```

shows the same version as the local file.

## Step 9: Give the app access

Print the app policy from the bundle. It needs no AWS call and fills in the
real key ARN, bundle id and environment. Never hand-write or widen it.

```sh
npx keyseal policy "secrets/$ENV.ks.json" > "/tmp/keyseal-$ENV-app-policy.json"
# with Step 8 done, add: --s3 "s3://$BUCKET/$ENV.ks.json"
```

Attach it to the app's role:

| Platform | Attach to |
|---|---|
| ECS / Fargate | The task role |
| EKS | The service account's IRSA or Pod Identity role |
| Lambda | The execution role |
| EC2 | The instance profile role |
| Platforms with OIDC | A new role that trusts the platform's issuer |
| Anything else | **Stop at S3.** Then an IAM user with only this policy. |

For a static key, you may create the IAM user and attach the policy, but the
user creates the access key (IAM console, "Create access key") and pastes
it straight into the platform as `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`, with `AWS_REGION`. Never run `aws iam
create-access-key` yourself: its output includes the secret.

**Check,** if the user has a CLI profile for the app's role:

```sh
AWS_PROFILE=<app-profile> npx keyseal status <bundle> --env "$ENV"
```

prints `Verified`. Otherwise ask the user to run it once from the app's
environment.

## Step 10: Hand over

Stop at S4. Tell the user to deploy, confirm the app works, then delete
the secrets from the platform's env store and any local plaintext files.
Don't delete them yourself.

Finish with a report in this shape:

```
keyseal setup
- Environments: production, staging
- KMS keys: alias/keyseal-production (arn:...), alias/keyseal-staging (arn:...)
- Bundles: secrets/production.ks.json (v3, 12 secrets), secrets/staging.ks.json (v2, 12 secrets)
- Loading: keyseal run in package.json "start" / library in src/secrets.ts
- Rotation source: s3://acme-keyseal/<env>.ks.json, published by .github/workflows/publish-secrets.yml
- App access: task role arn:... has the `keyseal policy` output (bundle-scoped kms:Decrypt, s3:GetObject)
- Verified: status as app role OK; development run check OK; tests pass
- For the user to do: deploy; delete plaintext vars from the platform; delete .env.production
- Optional hardening: docs/hardening.md
```

## Troubleshooting

| Error | Likely cause | Do |
|---|---|---|
| `key_unavailable` with `AccessDeniedException` | The identity lacks `kms:Decrypt` on the key, the policy was printed from a different bundle, or the bundle is from an epoch the policy revokes | Re-run `keyseal policy` on the bundle the app loads and compare. Don't widen it beyond that. |
| `key_unavailable` with `NotFoundException` or a region error | Wrong region for an alias | Pass `--region` or use the key ARN. |
| `env_mismatch` | The wrong bundle for this `--env` | Use the bundle for that environment. |
| `mac_mismatch` | The bundle was edited by hand or merged badly | Restore the last good version from git and redo the edit with `keyseal`. |
| `source_unavailable` for `s3://` | Missing `s3:GetObject`, wrong bucket region, or the object isn't published | Check the policy and `AWS_REGION`. |
| `rollback` | An older bundle than one already loaded or than `--min-version` | Publish the latest bundle. Never lower the minimum to get past it without asking. |
| `not valid secret names` from `import` | Names with dashes, dots or a leading digit | Report them. The app must rename them. |
| `... is not a local file` | A write command was given an `s3://` or URL bundle | Edit the local file, then publish it. |
| `key_unavailable` with `no local key` | A local bundle, and this machine has neither `KEYSEAL_KEY` nor the saved key | Stop and ask the user for access to the key. Never generate a new one to get past it. |
