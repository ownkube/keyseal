# Contributing

Thanks for helping. keyseal guards other people's secrets, so changes are
held to a careful bar, but the process is simple.

## Before you start

- **Security issues** never go in a public issue or PR. See
  [SECURITY.md](SECURITY.md).
- **Format or crypto changes** (anything in [spec/](spec)) start as an
  issue. The format is specified separately from the code so other
  languages can implement it, and changes there need agreement first.
- Small fixes and docs: open a PR directly.

## Setup

The library lives in [`ts/`](ts). You need Node 22.12 or later and pnpm
(the version is pinned in `ts/package.json`; `corepack enable` picks it up).

```sh
cd ts
pnpm install
pnpm test        # unit tests, no cloud access needed
pnpm check       # format, lint and types
pnpm build
```

`pnpm fix` formats and fixes what it can.

## Guidelines

- **No new runtime dependencies** in the core. It uses only WebCrypto.
  Provider packages pin their dependencies to exact versions.
- **Tests come with the change.** For anything that refuses input (a bad
  MAC, a revoked epoch, an unknown client), test the refusal, not only the
  happy path.
- **Never log a secret.** Not a value, a key, a token, or a data key, in
  code, tests, errors or docs examples.
- **Format changes** update `spec/FORMAT.md` and regenerate the vectors
  with `pnpm vectors` in the same PR.
- **User-facing changes** add a line to the top section of
  [CHANGELOG.md](CHANGELOG.md), and update the docs page that covers them.
- Docs are plain and short: one idea per sentence, commands that work as
  pasted.

## Releases

Maintainers release by bumping `ts/package.json`, adding the
`CHANGELOG.md` section, and pushing a `vX.Y.Z` tag. The
[release workflow](.github/workflows/release.yml) checks, tests, builds,
publishes to npm with provenance, and creates the GitHub release.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
