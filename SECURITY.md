# Security reporting

## Report privately

**GitHub private vulnerability reporting is enabled**, verified through the
repository API on 2026-09-21. Sign in to GitHub and use
[Report a vulnerability](https://github.com/voyager163/missionspec/security/advisories/new)
to send a private report to the maintainers. This route requires an eligible
GitHub account; it is not an anonymous reporting endpoint.

**Never post sensitive findings publicly**, including in issues, pull requests,
comments, attachments, or reproductions. This includes exploit details,
credentials, personal data, private source, `.env` files, and raw diagnostics.
A privacy problem that reveals sensitive information should be handled as a
security finding, not as a public support question.

If the private GitHub route is unavailable to you, retain the finding privately
rather than submitting it to an unsafe public channel. The conduct contact
in the [Code of Conduct](CODE_OF_CONDUCT.md) is for conduct reports only and is
**not** an approved security-reporting fallback. No other project security
address has been approved.

Enabling private intake does not establish a response-time guarantee or complete
repository hardening. The [maintainer guide](docs/maintainer-setup.md#private-reporting-publication-gate)
records the verified setting and remaining hosted CI/publication gates.

## Scope and supported versions

MissionSpec is pre-release. Its CLI supports explicitly reviewed local workflows,
skill installation, source-patch application and registered check collection.
Native autonomous execution and Windows private-state writes remain unqualified.
There is no production telemetry endpoint, cloud deployment or supported product
release. Findings concerning these development
components, source assets, repository tooling, or project configuration still
require a safe reporting channel; the absence of a product release does not
make them suitable for public disclosure.

There is no promised acknowledgement, remediation, or release-response time.
Repository checks and automated scanning do not constitute a security audit or
a guarantee that a change is safe.

## Non-sensitive questions and accidental exposure

Use [Issues](https://github.com/voyager163/missionspec/issues) for ordinary bugs
and general security or privacy questions only when the entire question is safe
to make public. Do not include details of an undisclosed vulnerability there.
Conduct concerns follow the separate [Code of Conduct](CODE_OF_CONDUCT.md).

If a credential has been exposed, revoke or rotate it with its provider promptly.
Do not post a replacement credential. Removing material from a public page does
not ensure that copies, notifications, or repository history have disappeared.
