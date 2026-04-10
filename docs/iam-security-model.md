# IAM Security Model

## Overview

This document describes the security model underpinning `iam-audit-lab` — what risks it
addresses, how it classifies them, and what is out of scope.

## Risk taxonomy

### Privilege escalation paths

IAM configurations often contain unintended privilege escalation paths where a principal with
limited permissions can acquire higher-level access:

- **Direct escalation**: A role has `iam:CreateAccessKey` or `iam:AttachUserPolicy`, allowing
  it to create credentials for or grant admin policies to any user.
- **Lateral movement via assume-role**: A low-privilege role can assume a high-privilege role
  because the trust policy is overly permissive.
- **Service-linked role abuse**: A principal can create a service-linked role that it can then
  assume.
- **Unrestricted role passing**: A principal with `iam:PassRole` on `Resource "*"` can pass any
  role to supported AWS services and indirectly gain the role's privileges.

The offline policy analyzer flags direct escalation indicators in exported AWS IAM policy JSON,
including wildcard actions, broad `sts:AssumeRole`, `NotAction`/`NotResource`, sensitive-data
access on broad resources, and unrestricted `iam:PassRole`.

### Credential persistence

Even well-configured accounts accumulate risk when credentials are not rotated and accounts are
not deprovisioned:

- **Long-lived access keys**: AWS access keys with no rotation create persistent attack surface.
- **Inactive accounts**: Compromised credentials go undetected when the account is dormant.
- **No expiry on service accounts**: GCP and Azure service account keys with no expiry date.

### Blast radius model

The risk score assigned to each finding reflects the potential blast radius if the identity is
compromised:

| Permission level | Blast radius | Risk contribution |
|---|---|---|
| AdministratorAccess / Owner | Entire account | 1.0 (critical) |
| Power user / Editor | All services except IAM | 0.75 (high) |
| Single-service admin (e.g., S3FullAccess) | All resources in one service | 0.5 (medium) |
| Read-only | No modification possible | 0.1 (low) |

## Attack scenarios

### Scenario 1: Compromised CI/CD service account

A deployment pipeline's service account has `AdministratorAccess`. An attacker compromises the
CI/CD platform and extracts the access key. The attacker can now:
- Create new IAM users with admin permissions (persistence)
- Exfiltrate all data from S3 buckets
- Modify or delete infrastructure

**Mitigation**: Replace `AdministratorAccess` with a least-privilege policy specific to the
deployment pipeline's actual needs.

### Scenario 2: Inactive employee account

An employee leaves the organization. Their account is not deprovisioned. Six months later, their
credentials are found in a breach database. The attacker logs in with the stolen password (no MFA
required) and exfiltrates data.

**Mitigation**: Enforce a 30-day deprovisioning SLA for departed employees. Enable MFA for all
accounts and enforce it via policy.

### Scenario 3: Orphaned service account with keys

A project is decommissioned but its service account and API keys are never deleted. A contractor
who worked on the project still has the API key saved locally. The contractor leaves and the key
is never rotated. Years later, the key is found and used.

**Mitigation**: Implement automated service account lifecycle management tied to project
decommissioning workflows. Audit for service accounts with no recent usage.

## What this tool does not detect

- **Permissions granted via resource-based policies** (e.g., S3 bucket policies, KMS key policies)
- **Service control policies (SCPs)** that restrict effective permissions
- **Permission boundaries** that limit the maximum permissions of a user/role
- **Runtime service constraints** that determine whether a specific `iam:PassRole` grant is
  exploitable with a matching compute or orchestration service
- **Zero-day vulnerabilities** in cloud provider IAM services
- **Insider threats** (an authorized user deliberately misusing their permissions)
