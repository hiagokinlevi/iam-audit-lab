# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes       |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in `iam-audit-lab`, please report it
responsibly by emailing **hiagokinlevi@protonmail.com**. Include:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce the issue.
3. Any proof-of-concept code (if applicable).
4. Your suggested fix or mitigation (optional but appreciated).

You can expect an acknowledgment within **48 hours** and a resolution plan within **7 days**
for confirmed critical issues.

## Scope

The following are in scope for security reports:

- Logic errors in permission analysis that cause critical findings to be missed
- Credential exposure in logs, output files, or error messages
- Issues that could allow unauthorized access to cloud APIs
- Dependency vulnerabilities with a direct exploit path in this library

The following are **out of scope**:

- Attacks that require full control of the host system
- Issues in upstream dependencies without a direct exploit path
- Findings about the *cloud environments being audited* (not this tool itself)

## Security Design Principles

1. **Read-only API access** — All cloud provider collectors use read-only API calls. The tool
   never writes to, modifies, or deletes any cloud resources.
2. **Credential isolation** — Credentials are loaded from environment variables or provider
   credential chains. They are never written to output files or audit logs.
3. **Sensitive output handling** — Reports contain identity names and permission details. These
   should be treated as sensitive data and stored in access-controlled locations.
4. **Minimal permissions** — The required permission sets are documented and kept as narrow as
   possible. See the README for the exact permissions required per provider.

## Disclosure Policy

We follow a **coordinated disclosure** model. Once a vulnerability is confirmed and a fix is
available, we will:

1. Publish a security advisory on GitHub.
2. Release a patched version.
3. Credit the reporter (unless they prefer anonymity).
