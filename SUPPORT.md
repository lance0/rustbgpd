# Adopter support

rustbgpd is public alpha overall, including its route-reflector and IXP
route-server niche. This document explains how adopters can report problems
and how to interpret the project's compatibility and proof claims. It does not
declare production readiness.

## Compatibility boundary

The only narrow compatibility promise is the machine-inventoried
[route-server / route-reflector v1 contract](docs/v1-stable-contract.md).
That promise applies only to the roles and surfaces listed by its inventory.
The rest of the project remains alpha and may change between minor releases.

RFC 8212 enforcement remains opt-in under
[ADR-0112](docs/adr/0112-rfc-8212-ebgp-requires-policy.md).
[ADR-0119](docs/adr/0119-rfc-8212-secure-default-config-epoch.md) is Proposed;
it does not activate a secure default.

## Reporting an ordinary bug

Open an issue with the
[bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include:

- the rustbgpd version or commit;
- the OS, kernel, and peer implementation versions;
- minimal reproduction steps, expected behavior, and observed behavior; and
- relevant redacted logs or configuration snippets.

When possible, attach the redacted support bundle produced by `rbgp doctor`;
the [operations guide](docs/OPERATIONS.md#support-bundles-and-triage-checks-rbgp-doctor)
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
[release checklist](docs/RELEASE_CHECKLIST.md) defines gates that must pass
before a tag; neither document is a release schedule.

Proof receipts establish only the named fixtures, software versions,
environments, and assertions recorded in each receipt. They do not establish
general production support. Start with the
[operational proof index](docs/OPERATIONAL_PROOF.md) and inspect the linked
[receipt catalog](docs/RECEIPTS.md), [interoperability matrix](docs/INTEROP.md),
and methodology before applying a result to a different environment.
