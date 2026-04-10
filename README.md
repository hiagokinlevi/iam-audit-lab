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
    └── generate-report     ──►  Report generator (Markdown)
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
| **GCP** | IAM members, service accounts | Application Default Credentials |
| **Entra ID** | Users, service principals, groups | azure-identity (same as Azure) |

---

## Quick Start

### Installation

```bash
pip install iam-audit-lab
```

### Configure credentials

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Set your cloud provider credentials:

- **AWS**: Set `AWS_PROFILE` or configure environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- **Azure**: Set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
- **GCP**: Set `GOOGLE_APPLICATION_CREDENTIALS` to your service account key file path

### Run your first audit

```bash
# Collect all IAM identities from AWS
k1n-iam-audit collect-identities --provider aws

# Analyze for excessive permissions
k1n-iam-audit analyze-privileges --provider aws

# Review an exported AWS IAM policy without cloud credentials
k1n-iam-audit analyze-policy --policy-file ./policy.json --policy-name deploy-policy --fail-on high

# Check MFA coverage
k1n-iam-audit analyze-mfa --provider aws

# Find inactive accounts (no activity in 90 days)
k1n-iam-audit analyze-inactive --provider aws --inactive-days 90

# Generate a full report
k1n-iam-audit generate-report --provider aws --output ./output/aws_audit_report.md
```

---

## Required Permissions

### AWS

The following **read-only** IAM permissions are required:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListGroups",
        "iam:ListRoles",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListMFADevices"
      ],
      "Resource": "*"
    }
  ]
}
```

### Azure

Required role: **Reader** on the subscription + **Directory Reader** in Azure AD.

### GCP

Required role: **roles/iam.securityReviewer** on the project.

---

## Key Components

| Module | Purpose |
|---|---|
| `providers/aws/identity_collector.py` | Collects IAM users and roles from AWS |
| `providers/azure/identity_collector.py` | Collects Azure AD users and service principals |
| `providers/gcp/identity_collector.py` | Collects GCP IAM members and service accounts |
| `analyzers/excessive_permissions/analyzer.py` | Detects overly broad permissions |
| `analyzers/iam_policy_analyzer.py` | Reviews exported AWS IAM policy JSON for wildcard, data-access, NotAction/NotResource, and PassRole risks |
| `analyzers/inactive_accounts/analyzer.py` | Identifies dormant accounts |
| `analyzers/mfa_coverage/analyzer.py` | Measures MFA enrollment |
| `schemas/identity.py` | Pydantic models for normalized identity data |
| `reports/generator.py` | Markdown report generator |
| `cli/main.py` | Click CLI entry point |

---

## Output Example

```
IAM Audit Report — AWS Account 123456789012
Generated: 2025-01-15T14:30:00Z

## Executive Summary

| Metric | Value | Risk |
|---|---|---|
| Total identities | 47 | — |
| Inactive (>90 days) | 8 | MEDIUM |
| Missing MFA (human accounts) | 3 | HIGH |
| Overly broad permissions | 2 | CRITICAL |

## Critical Findings

1. [CRITICAL] User 'deploy-bot' has AdministratorAccess attached
2. [HIGH] 3 human users do not have MFA enabled
3. [MEDIUM] 8 accounts show no activity in the last 90 days
```

---

## Ethical Use and Authorization

**Only run this tool against cloud accounts you own or are explicitly authorized to audit.**

IAM collectors use read-only API calls but still access potentially sensitive information about
your organization's users, roles, and permission structures. Handle audit output as sensitive data:

- Store reports in access-controlled locations
- Do not commit reports to version control
- Redact or pseudonymize user identifiers before sharing externally
- See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features.

## License

[CC BY 4.0](LICENSE) — Copyright (c) 2025 Hiago Kin Levi
