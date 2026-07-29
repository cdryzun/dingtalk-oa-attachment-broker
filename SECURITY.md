# Security Policy

## Supported Versions

Security fixes are applied to the latest release and the default branch. Older
releases may require an upgrade before a fix can be applied.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting form in the repository Security
tab. Do not open a public issue for a suspected vulnerability.

Include the affected version or commit, deployment assumptions, reproduction
steps, impact, and any proposed mitigation. Remove all DingTalk credentials,
Broker tokens, OAuth codes, signed URLs, approval content, attachment content,
enterprise identifiers, and personal data from the report.

The maintainer will validate the report, coordinate remediation, and publish an
advisory when disclosure is appropriate. No response or resolution deadline is
promised by this volunteer-maintained project.

## Security Boundary

This project protects access to DingTalk OA approval attachments. Reports about
authentication, authorization, session rotation, audit integrity, SSRF,
redirect validation, DNS rebinding, filename handling, credential disclosure,
or cross-approval attachment access are in scope.

Vulnerabilities in DingTalk itself, an operator's TLS proxy, PostgreSQL,
container platform, secret manager, or downstream handling of already
authorized attachment bytes should be reported to the responsible vendor or
operator unless the Broker directly creates or amplifies the issue.

Review [docs/threat-model.md](docs/threat-model.md) for documented controls and
residual risks.
