# Audit Methodology

This document describes the methodology used by `iam-audit-lab` to collect data, analyze
it for security issues, and score findings.

---

## Collection phase

### Data sources

| Provider | API | Identity types collected |
|---|---|---|
| AWS | IAM API (boto3) | Users, roles |
| Azure | Microsoft Graph API | Users, service principals |
| GCP | Cloud IAM API | Service accounts, IAM policy members |
| Entra ID | Microsoft Graph API | Users, service principals |

### Data normalization

All provider-specific identity formats are converted to `IdentityRecord` objects. Fields that
cannot be populated from a given provider are set to `None`.

Key normalized fields:
- `identity_type`: `human`, `service`, `group`, or `unknown`
- `last_activity_at`: ISO 8601 string or `"never"`
- `mfa_enabled`: Boolean (False as conservative default when data is unavailable)
- `is_privileged`: Boolean, set by heuristic policy matching

---

## Analysis phase

### Excessive permissions analysis

For each identity, `attached_policies` is compared against a dictionary of known high-privilege
policy/role names. A finding is produced for each match.

**Scoring:**
- Critical policies (e.g., AdministratorAccess): risk score 1.0
- High-privilege policies (e.g., PowerUserAccess): risk score 0.75
- Medium-privilege policies (e.g., AmazonS3FullAccess): risk score 0.5

### Inactive account analysis

For each identity with `last_activity_at` set, the time since last activity is calculated.
If the time exceeds the configured threshold (default: 90 days), a finding is produced.

**Scoring:**
- Inactive + privileged: risk score 0.7
- Inactive (non-privileged): risk score 0.45
- Orphaned (never used, created > threshold days ago): risk score 0.4

### MFA coverage analysis

For each human identity (`identity_type == "human"`), `mfa_enabled` is checked.

**Scoring:**
- Privileged without MFA: risk score 0.95 (critical)
- Non-privileged without MFA: risk score 0.65 (high)

---

## Scoring and severity mapping

Individual finding scores map to severity levels as follows:

| Score range | Severity |
|---|---|
| 0.8 – 1.0 | Critical |
| 0.6 – 0.79 | High |
| 0.4 – 0.59 | Medium |
| 0.2 – 0.39 | Low |
| 0.0 – 0.19 | Informational |

Aggregate identity risk scores are computed as a weighted average across analyzer scores,
with weights configurable via environment variables.

---

## Report generation

Reports are generated in Markdown format. Two report types are available:

1. **Executive summary**: Key metrics, critical/high findings only. Suitable for leadership review.
2. **Full report**: All findings, complete identity inventory, remediation guidance. Suitable for
   engineering teams and compliance reviews.

Reports are saved to the `./output/` directory by default.

---

## Scope and limitations

- **Point-in-time snapshot**: The tool captures a point-in-time view of the IAM configuration.
  Changes made after collection are not reflected.
- **Heuristic-based analysis**: Permission analysis is based on known policy names. Custom
  policies with broad permissions are not detected in v0.1.
- **No write access validation**: The tool does not verify whether permissions actually work
  (e.g., a policy may be attached but superseded by an SCP). Findings reflect configuration,
  not effective permissions.
