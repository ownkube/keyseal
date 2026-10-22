# keyseal Worker

A keyseal key service on your own Cloudflare account. It holds the wrapping
key as a Worker secret and unwraps a bundle's data key only for the apps
you list, logging every request. Fits in the Workers free plan.

```sh
cp -r worker keyseal-worker && cd keyseal-worker   # or copy these four files
npm install
npx keyseal key --new             # save this in your password manager first
npx wrangler secret put KEYSEAL_KEY   # paste it here
npm run deploy
```

Cloudflare never shows a secret again, and without your saved copy nobody
can open the bundles it sealed once the Worker is gone.

Then list who may use it in `wrangler.jsonc` and deploy again. The full
walkthrough, including OIDC for Vercel, Fly and GitHub Actions, is in
[docs/cloudflare.md](../docs/cloudflare.md).
