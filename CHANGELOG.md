# Changelog

## 0.1.0

First release.

- Bundle format v1: one JSON file per environment, values encrypted with
  AES-256-GCM under a per-bundle data key, a MAC over the whole file, and
  conformance vectors in `spec/testvectors`.
- Key providers: AWS KMS, local keys, and a Cloudflare Worker you run on
  your own account (`@ownkube/keyseal/cloudflare`), with token or OIDC
  clients and an audit line per request.
- Rotation without a deploy: poll a bundle from S3 or any HTTPS URL, with
  grace windows for the previous value.
- Revoking old bundles by key epoch: an IAM Deny for KMS, `minEpoch` for
  the Worker.
- CLI: `init`, `import`, `set`, `rotate`, `rekey`, `ls`, `status`, `run`
  (with `--watch`), `policy`, `key`, `token`, and more. See
  `docs/reference.md`.
