# Overview

## What is iam-audit-lab?

`iam-audit-lab` is a Python CLI and library for auditing IAM (Identity and Access Management)
configurations across AWS, Azure, GCP, and Microsoft Entra ID. It collects identity data from
cloud provider APIs and runs analyzers to surface security findings.

## Why IAM auditing matters

IAM misconfigurations are among the most common causes of cloud security incidents:

- **Excessive permissions** — Service accounts and users with admin-level access that only need
  narrow, purpose-specific permissions.
- **Inactive accounts** — Former employees, decommissioned services, or forgotten test accounts
  that retain their permissions indefinitely.
- **MFA gaps** — Human accounts that can be accessed with only a password, making them vulnerable
  to credential theft.
- **Orphaned accounts** — Provisioned but never activated accounts that accumulate over time.

## Design principles

1. **Read-only** — The tool never modifies, creates, or deletes cloud resources. All API calls
   are strictly read-only.
2. **Normalized schema** — All provider-specific identity formats are converted to a common
   `IdentityRecord` schema, allowing analyzers to work across providers.
3. **Auditable output** — Reports are generated as Markdown files that can be committed to a
   secure repository, attached to tickets, or reviewed in pull requests.
4. **Explicit authorization scope** — Required permissions are documented and minimized. The tool
   refuses to accept wildcard credentials or overly broad permission grants.

## How it works

1. A **collector** connects to a cloud provider's API and retrieves identity records.
2. Each record is normalized into an `IdentityRecord` Pydantic model.
3. **Analyzers** process the normalized records and produce `AuditFinding` objects.
4. The **report generator** formats findings and identity data into Markdown reports.
5. The **CLI** orchestrates collectors, analyzers, and the report generator.

## Scope limitations

- AWS: Does not analyze CloudTrail for access key usage (planned for v0.2)
- Azure: MFA status requires Azure AD Premium P1/P2
- GCP: Human user collection requires Cloud Identity / Workspace Admin SDK (planned for v0.2)
- All providers: Custom roles/policies with broad permissions are not analyzed in v0.1
