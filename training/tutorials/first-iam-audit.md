# Tutorial: Your First IAM Audit with iam-audit-lab

This tutorial guides you through running a complete IAM audit on an AWS account. By the end,
you will have:

1. Collected all IAM identities from an AWS account
2. Identified accounts with excessive permissions
3. Checked MFA coverage
4. Found inactive accounts
5. Generated a full audit report

## Prerequisites

- Python 3.11+
- An AWS account you own or are authorized to audit
- An IAM user or role with the read-only permissions listed in the README

## Step 1: Install and configure

```bash
pip install iam-audit-lab
cp .env.example .env
```

Edit `.env`:

```
PROVIDER=aws
AWS_PROFILE=security-audit   # Use a dedicated read-only profile
AWS_REGION=us-east-1
INACTIVE_THRESHOLD_DAYS=90
```

## Step 2: Collect identities

```bash
k1n-iam-audit collect-identities --provider aws --output ./output/identities.json
```

Expected output:
```
Collecting identities from AWS...
Collected 47 identities.

Summary:
  Human accounts:   12
  Service accounts: 35
  Privileged:       4
```

The collected identities are saved to `./output/identities.json` for offline analysis.

## Step 3: Analyze for excessive permissions

```bash
k1n-iam-audit analyze-privileges \
  --provider aws \
  --identities-file ./output/identities.json
```

Expected output:
```
Analyzing 47 identities for excessive permissions...

Findings: 3 total
  Critical: 1
  High:     1
  Medium:   1
  Low:      0

Top findings:
  [CRITICAL] Excessive policy attached: AdministratorAccess
  [HIGH] Excessive policy attached: PowerUserAccess
  [MEDIUM] Excessive policy attached: AmazonS3FullAccess
```

## Step 4: Check MFA coverage

```bash
k1n-iam-audit analyze-mfa \
  --provider aws \
  --identities-file ./output/identities.json
```

Expected output:
```
Analyzing MFA coverage for 47 identities...

Total human accounts: 12
MFA enabled:          9 (75.0%)
MFA not enabled:      3
Privileged w/o MFA:   1
Compliant:            NO
```

## Step 5: Find inactive accounts

```bash
k1n-iam-audit analyze-inactive \
  --provider aws \
  --identities-file ./output/identities.json \
  --inactive-days 90
```

## Step 6: Generate a full report

```bash
k1n-iam-audit generate-report \
  --provider aws \
  --identities-file ./output/identities.json \
  --output ./output/aws_iam_audit_$(date +%Y%m%d).md
```

This runs all analyzers and generates a comprehensive Markdown report at the specified path.

## Step 7: Review and act on findings

Open the generated report. Critical findings should be addressed first:

1. **AdministratorAccess on service accounts** — Replace with a least-privilege policy.
   Use the IAM policy prompts in `docs/prompts/iam_audit_prompts.md` to generate a suitable
   replacement policy.

2. **Privileged account without MFA** — Enable MFA immediately. Enforce it via IAM policy:
   ```json
   {"Effect": "Deny", "Action": "*", "Resource": "*",
    "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}}
   ```

3. **Inactive accounts** — Disable or delete accounts with no recent activity. Coordinate
   with HR to ensure departing employees' accounts are deprovisioned within 24 hours.

## Next steps

- Schedule regular audits (weekly or monthly) and track findings over time
- Set up automated alerts for new privileged account creation
- Review the [docs/iam-security-model.md](../docs/iam-security-model.md) for deeper context
- Work through [training/labs/lab_01_aws_iam.md](../training/labs/lab_01_aws_iam.md) for
  hands-on practice with a simulated AWS environment
