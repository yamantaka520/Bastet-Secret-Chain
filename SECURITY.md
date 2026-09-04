# Security Policy

Bastet Secret Chain stores credentials. A defect here is a credential breach, so
security reports take precedence over every other kind of issue.

## Reporting a vulnerability

Report privately through GitHub Security Advisories on this repository. Do not
open a public issue, and do not include real credentials, real vault files, or
real tokens in a report — a redacted reproduction is always sufficient.

Expect an acknowledgement within 72 hours and an assessment within 7 days.

## Scope

In scope: cryptographic design and implementation, the seal/unseal lifecycle,
token scoping and revocation, the audit chain, secret handling in the daemon and
Web UI, service installation and file permissions, and any path where secret
material could reach a URL, log, process argument, crash report, or telemetry.

Out of scope: a compromised host OS, an attacker with the operator's live
session, hardware attacks, and coercion of the operator. These are recorded as
out of scope in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Verifying a release

Every release carries `SHA256SUMS`. From v0.2.0 that file is also signed with
Sigstore keyless signing, and the signature is a `.cosign.bundle` beside it:

```sh
cosign verify-blob --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp "^https://github.com/yamantaka520/Bastet-Secret-Chain/.github/workflows/release.yml@refs/tags/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS            # then the archives against the sums
```

Build provenance is attested as well:

```sh
gh attestation verify bsc-<version>-<target>.tar.gz --repo yamantaka520/Bastet-Secret-Chain
```

Understand what this proves and what it does not. It proves the artifact was
built by this repository's release workflow from this tag. It does **not**
prove that a maintainer reviewed that tag: anyone who can push a tag here can
produce a valid signature. There is no project signing key, and v0.1.0's
artifacts predate signing entirely.

## Operating guidance

- Keep the daemon on `127.0.0.1` unless you have a specific need and have read
  the exposure requirements in the master plan.
- Mint the narrowest agent token that does the job, with the shortest usable
  expiry. Prefer per-task tokens over standing ones.
- Keep approval-required on for cloud root keys, service accounts, and signing
  certificates.
- Run `bsc audit verify` periodically, and review denied reads.
- Never paste a secret into an agent prompt. Give the agent a reference and a
  token instead.

## Installing

Release archives are verified by `scripts/install.sh` / `install.ps1` against
the `SHA256SUMS` published with the same release. That proves the archive is
the one the release job produced, not that the release job was the
maintainer's — signed releases are scheduled for M7. Prefer building from
source until then, and never pipe an install script from the network into a
shell without reading it.

## Never in this repository

Vault databases, key material, exported secrets, service-account JSON, OAuth
client secrets, SSH keys, certificates, tokens, or audit ledgers — including in
tests, fixtures, issues, and pull requests. Test fixtures use generated
throwaway values only.
