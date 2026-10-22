# A key service on Cloudflare (no AWS account)

The keyseal Worker holds your wrapping key as a secret in **your**
Cloudflare account. When an app starts, it sends the bundle's wrapped data
key to the Worker, and the Worker unwraps it only for the apps you list.
Every request is logged. It fits in the Workers free plan.

Compared with [local keys](local.md), the key never sits in your
platform's env store. With OIDC, the platform stores no secret at all, only
the Worker's URL. What it does and doesn't protect against is in the
[threat model](../spec/THREAT_MODEL.md#cloudflare-worker-mode).

## 1. Deploy the Worker

Copy the [`worker/`](../worker) directory from this repo into a new
directory, then:

```sh
cd keyseal-worker
npm install
npx keyseal key --new
```

`key --new` prints a fresh key. **Save it in your password manager
first.** Cloudflare never shows a secret again, and if the Worker is
deleted, that copy is the only way to open the bundles it sealed. Treat it
like a root credential: it opens every bundle without asking the Worker.

Then store it in the Worker, pasting the key at the prompt, and deploy:

```sh
npx wrangler secret put KEYSEAL_KEY
npm run deploy
```

`npm run deploy` prints the Worker's URL, for example
`https://keyseal.acme.workers.dev`. Check it answers:

```sh
curl https://keyseal.acme.workers.dev/
# {"keyseal":"worker","version":1}
```

A new Worker refuses every request, because `KEYSEAL_ACCESS` in
`wrangler.jsonc` lists nobody yet.

## 2. Let yourself in

People who create and edit bundles use an editor token:

```sh
npx keyseal token
```

The token goes to stdout: save it in your password manager. The line on
stderr is its hash. Add a client with that hash to `wrangler.jsonc` and
deploy again:

```jsonc
"vars": {
  "KEYSEAL_ACCESS": {
    "clients": [
      { "name": "alice", "role": "editor", "env": "production", "token": "sha256:..." }
    ]
  }
}
```

Hashes aren't secret, so `wrangler.jsonc` can be committed. An editor may
create bundles and rekey them, for the environments in `env` (one name or a
list; leave it out for every environment).

In your shell, set the URL and read the token at a hidden prompt:

```sh
export KEYSEAL_WORKER_URL=https://keyseal.acme.workers.dev
read -rs KEYSEAL_WORKER_TOKEN && export KEYSEAL_WORKER_TOKEN
```

## 3. Create a bundle

```sh
npx keyseal init secrets/production.ks.json --env production --worker "$KEYSEAL_WORKER_URL"
npx keyseal import secrets/production.ks.json .env.production
git add secrets/production.ks.json
```

The bundle never stores the Worker's URL. Every reader passes it with
`--worker` or `KEYSEAL_WORKER_URL`, so an edited bundle can't send your
app to someone else's server.

## 4. Let the app in

Print the app's entry for this bundle:

```sh
npx keyseal policy secrets/production.ks.json
```

```json
{
  "clients": [
    { "name": "production-app", "role": "app", "env": "production", "bundle": "Xq3m0yJw6Zr1k2v9Qp7tLg", "token": "sha256:PASTE_FROM_KEYSEAL_TOKEN" }
  ]
}
```

An app may only unwrap, only for that bundle and environment. Then give it
a credential, either an OIDC identity from the platform (better: nothing to
leak) or a token.

### With a token

Make the token and pipe it straight into the platform, so it never shows
on screen:

```sh
npx keyseal token | vercel env add KEYSEAL_WORKER_TOKEN production
npx keyseal token | sed 's/^/KEYSEAL_WORKER_TOKEN=/' | fly secrets import
```

The hash prints on stderr. Paste it over `PASTE_FROM_KEYSEAL_TOKEN`, merge
the entry into `KEYSEAL_ACCESS`, and deploy the Worker.

If the platform has fixed outbound addresses, pin them, and the token is
useless anywhere else:

```json
{ "name": "production-app", "role": "app", "env": "production", "bundle": "...", "token": "sha256:...", "ips": ["203.0.113.0/24", "2001:db8::/32"] }
```

Set `KEYSEAL_WORKER_URL` on the platform too, and start the app as usual:

```sh
npx keyseal run secrets/production.ks.json --env production -- node server.js
```

`run` removes `KEYSEAL_WORKER_TOKEN` from the command's environment. From
code, `worker()` reads both variables:

```ts
import { createKeyseal, worker } from "@ownkube/keyseal";

export const secrets = await createKeyseal({
  source: "secrets/production.ks.json",
  keys: worker(),
  env: "production",
});
```

### With OIDC

Use `oidc` in place of `token`. The Worker checks the platform's
signature, the issuer, the audience, and the `subject` or `claims` you
give. Use your Worker's URL as the audience, so a token the app hands to
some other service can't be replayed here.

**Vercel** (issuer mode "team" in the project's OIDC settings):

```json
{
  "name": "production-app", "role": "app", "env": "production", "bundle": "...",
  "oidc": {
    "issuer": "https://oidc.vercel.com/acme",
    "audience": "https://keyseal.acme.workers.dev",
    "subject": "owner:acme:project:web:environment:production"
  }
}
```

A function only has its token while it handles a request, so load secrets
on the first request rather than at import:

```ts
import { createKeyseal, inline, type Keyseal, worker } from "@ownkube/keyseal";
import { getVercelOidcToken } from "@vercel/oidc";
import bundle from "../secrets/production.ks.json" with { type: "json" };

let secrets: Promise<Keyseal> | undefined;

export function getSecrets(): Promise<Keyseal> {
  secrets ??= createKeyseal({
    source: inline(JSON.stringify(bundle)),
    keys: worker({
      token: () => getVercelOidcToken({ audience: "https://keyseal.acme.workers.dev" }),
    }),
    env: "production",
  }).catch((e) => {
    secrets = undefined;
    throw e;
  });
  return secrets;
}
```

with `KEYSEAL_WORKER_URL` set in the project. Renaming the team or project
changes the subject; update the entry first.

**Fly.io.** The subject includes the machine name, so match the app by
claim instead:

```json
"oidc": {
  "issuer": "https://oidc.fly.io/acme",
  "audience": "https://keyseal.acme.workers.dev",
  "claims": { "app_name": "web" }
}
```

Fetch a token at startup in the start command:

```sh
KEYSEAL_WORKER_TOKEN="$(curl -sf --unix-socket /.fly/api -X POST http://localhost/v1/tokens/oidc \
  --data '{"aud":"https://keyseal.acme.workers.dev"}')" \
  exec npx keyseal run secrets/production.ks.json --env production -- node server.js
```

The token lasts minutes, which covers startup. After a `rekey`, restart
the app so it fetches a fresh one, or use the library with a `token`
function that asks `/.fly/api` each time.

**GitHub Actions**, for jobs that need secrets (end-to-end tests, a
deploy). Match on the repository id and a protected environment, which
survive renames and work with either `sub` format:

```json
"oidc": {
  "issuer": "https://token.actions.githubusercontent.com",
  "audience": "https://keyseal.acme.workers.dev",
  "claims": { "repository_id": "123456789", "environment": "ci" }
}
```

`gh api repos/acme/web --jq .id` prints the id. In the workflow:

```yaml
jobs:
  e2e:
    environment: ci
    permissions:
      contents: read
      id-token: write
    env:
      KEYSEAL_WORKER_URL: https://keyseal.acme.workers.dev
    steps:
      - uses: actions/checkout@v5
      - run: npm ci
      - run: |
          KEYSEAL_WORKER_TOKEN="$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://keyseal.acme.workers.dev" | jq -r .value)" \
            npx keyseal run secrets/ci.ks.json --env ci -- npm run e2e
```

## 5. Check it

```sh
npx keyseal status secrets/production.ks.json --env production
```

prints `Verified` with an editor token. Run the same with the app's
credential, from the app's environment, to check its entry.

## Audit log

The Worker writes one line per request to Workers Logs (Observability in
the dashboard, or `npm run logs` for a live tail):

```json
{"keyseal":"request","at":"2026-10-22T10:02:11.402Z","ip":"203.0.113.7","op":"decrypt","bundle":"Xq3m0yJw6Zr1k2v9Qp7tLg","env":"production","epoch":1,"keyId":"Lw8...","client":"production-app","status":200}
```

Refusals carry a `reason`. Lines never contain tokens or keys. The free
plan keeps logs for 3 days; export them with Logpush or `wrangler tail` if
you need longer.

## What one app can do

An app that can unwrap a bundle holds that bundle's data key. With write
access to wherever the bundle lives, it could also re-seal an edited copy,
which no Worker check sees, because editing reuses the data key. The app
role only stops it creating bundles and rekeying. The same holds for KMS,
where `kms:Decrypt` is enough. Keep write access to the repo, bucket or URL
for people and your publishing CI job.

## Cut off a credential

Remove the client from `KEYSEAL_ACCESS` and deploy the Worker. Further
requests get 401 within seconds, with no app deploy. Running processes
keep the values they already have, so rotate those at their providers as
in the [incident playbook](hardening.md#incident-playbook).

## Revoke old bundles

After `keyseal rekey`, the bundle moves to the next epoch and
`keyseal policy` prints a `minEpoch` for it:

```json
"minEpoch": { "Xq3m0yJw6Zr1k2v9Qp7tLg": 2 }
```

Add it to `KEYSEAL_ACCESS` once every app runs the new bundle. From then on
the Worker refuses every older copy of that bundle with 403, including
ones in git history.

## Change the Worker's key

1. Run `npx keyseal key --new` and save the key in your password manager.
   Then `npx wrangler secret put KEYSEAL_KEY` and paste the new key and
   the old one, separated by a space. The first key seals new bundles;
   both open existing ones.
2. `npx keyseal rekey <file>` each bundle, publish, and wait for apps to
   pick them up. Add `minEpoch` for each.
3. Set `KEYSEAL_KEY` to the new key alone. Bundles still on the old key now
   get 404.

## Free plan limits

| | Free plan | keyseal use |
|---|---|---|
| Requests | 100,000 a day | One per process start, plus one per rekey |
| CPU | 10 ms per request | Well under; OIDC keys are cached for 10 minutes |
| Workers Logs | 200,000 events a day, 3 days | One line per request |

Rotating a value reuses the data key, so it costs no Worker requests.
