# Adopter support

rustbgpd is public alpha overall, including its route-reflector and IXP
route-server niche. This document explains how adopters can report problems
and how to interpret the project's compatibility and proof claims. It does not
declare production readiness.

## Compatibility boundary

The only narrow compatibility promise is the machine-inventoried
[route-server / route-reflector v1 contract](docs/reference/v1-stable-contract.md).
That promise applies only to the roles and surfaces listed by its inventory.
The rest of the project remains alpha and may change between minor releases.

## Platform support

The distributed and supported `rustbgpd` daemon targets are Linux x86_64 and
Linux aarch64. Published binaries use a glibc 2.31 baseline; see the
[deployment guide](docs/how-to/deployment.md#pre-built-binary-tarball). macOS, BSD,
and Windows daemon builds are unsupported: they may not compile or run, and
there is no degraded daemon mode for those systems.

The release workflow can build and runtime-verify containers natively on Linux
x86_64 and Linux aarch64, then publish a single multi-arch (amd64+arm64)
manifest on a tagged release. It does not backfill existing images: `:0.68.0`
and `:0.68` remain amd64-only. `:latest` follows the newest non-prerelease
release and inherits that release's platform set. Broader daemon support,
interoperability, and privileged CI remain Linux x86_64; release packages and
tarballs use their documented cross-build path where applicable. Pure,
kernel-independent crates and transport or socket abstractions with non-Linux
fallbacks may remain portable and testable; that does not expand daemon
platform support.

RFC 8212 enforcement remains opt-in under
[ADR-0112](docs/adr/0112-rfc-8212-ebgp-requires-policy.md).
[ADR-0119](docs/adr/0119-rfc-8212-secure-default-config-epoch.md) is Accepted;
its representation, advisory, and offline migration/downgrade tooling are
shipped, but acceptance still does not activate a secure default. Migration is
Linux-only and requires an explicit config path; downgrade also
requires an explicitly selected exact v0.64.0 validator binary.

## Reporting an ordinary bug

Open an issue with the
[bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include:

- the rustbgpd version or commit;
- the OS, kernel, and peer implementation versions;
- minimal reproduction steps, expected behavior, and observed behavior; and
- relevant redacted logs or configuration snippets.

When possible, attach the redacted support bundle produced by `rbgp doctor`;
the [operations guide](docs/reference/operations.md#support-bundles-and-triage-checks-rbgp-doctor)
describes its contents and collection options. Review attachments for
environment-specific sensitive information before publishing them.

No response time, resolution time, maintenance window, backport policy, or
release cadence is promised for ordinary reports.

## Reporting a vulnerability

Follow the root [security policy](SECURITY.md) and use its private reporting
channel. Never report a vulnerability in a public issue. The security policy's
separate handling timeline applies only to qualifying vulnerability reports;
it is not an ordinary-support commitment.

## Releases and proof

The [changelog](CHANGELOG.md) records release history and notable changes. The
[release checklist](docs/project/release-checklist.md) defines gates that must pass
before a tag; neither document is a release schedule.

Proof receipts establish only the named fixtures, software versions,
environments, and assertions recorded in each receipt. They do not establish
general production support. Start with the
[operational proof index](docs/operational-proof.md) and inspect the linked
[receipt catalog](docs/receipts.md), [interoperability matrix](docs/interop.md),
and methodology before applying a result to a different environment.
