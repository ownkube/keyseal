# Security

Report vulnerabilities to security@ownkube.io, or privately through
GitHub's "Report a vulnerability" on this repository. Please don't open a
public issue.

keyseal is pre-1.0 and has not had an external security review. What it
protects against, and what it doesn't, is in
[spec/THREAT_MODEL.md](spec/THREAT_MODEL.md).

Releases are published from GitHub Actions with npm trusted publishing and
provenance. Check a release with `npm audit signatures`.
