# iam-audit-lab

> Multicloud IAM audit tools for AWS, Azure, GCP, and Entra — identify excessive permissions,
> orphaned accounts, and MFA gaps.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)

---

## Overview

IAM misconfigurations are consistently among the top causes of cloud security incidents. Accounts
with excessive permissions, unused service principals, and MFA gaps create attack surface that
adversaries actively exploit.

`iam-audit-lab` provides a unified command-line interface and Python library for auditing
IAM configurations across AWS, Azure, GCP, and Microsoft Entra ID. It produces structured
findings and human-readable reports that help security and platform teams:

- Identify accounts with excessive or unused permissions
- Flag GCP IAM policies that grant project roles to `allUsers` or `allAuthenticatedUsers`
- Review exported AWS IAM policy JSON offline for wildcard and PassRole escalation risk
- Find inactive users and service accounts that should be deprovisioned
- Measure MFA coverage for privileged and non-privileged accounts
- Generate reports for compliance reviews and security audits

---

## Architecture

```
CLI (click)
    │
    ├── collect-identities  ──►  Provider collectors
    │                              ├── AWS IAM (boto3)
    │                              ├── Azure AD (azure-identity)
    │                              └── GCP IAM (google-cloud-iam)
    │
    ├── analyze-privileges  ──►  Excessive permissions analyzer
    ├── analyze-policy      ──►  Offline AWS IAM policy analyzer
    ├── analyze-mfa         ──►  MFA coverage analyzer
    ├── analyze-inactive    ──►  Inactive accounts analyzer
    │
    └── generate-report     ──►  Report generator (Markdown / JSON)
                                   ├── Executive summary
                                   ├── Full inventory
                                   ├── MFA coverage table
                                   └── Privileged accounts list
```

---

## Supported Providers

| Provider | Identity Types | Auth Method |
|---|---|---|
| **AWS** | IAM users, IAM roles | boto3 session (profile or environment) |
| **Azure** | Azure AD users, service principals | azure-identity (DefaultAzureCredential) |
| **GCP** | IAM members, service accounts | |

---

## CLI usage snippet

Use a stricter inactivity threshold in production audits:

```bash
iam-audit-lab analyze-inactive \
  --input data/identities.json \
  --output data/inactive-findings.json \
  --max-age-days 30
```

`--max-age-days` must be a positive integer and defaults to `90` days.
