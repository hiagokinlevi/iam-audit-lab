# Lab 01: AWS IAM Security Review

**Estimated time:** 60–90 minutes
**Difficulty:** Beginner
**Prerequisites:** AWS account, iam-audit-lab installed, basic IAM knowledge

---

## Objective

In this lab you will:
1. Set up a controlled AWS IAM environment with known security issues
2. Run the iam-audit-lab tools to discover those issues
3. Interpret the findings
4. Remediate one finding end-to-end

---

## Lab setup

### Create the test IAM users (CloudFormation)

Save the following as `lab-01-setup.yaml` and deploy it with CloudFormation.

**Warning:** This template creates IAM users with intentionally insecure configurations.
Only deploy in an isolated sandbox account. Delete the stack when done.

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Lab 01 — iam-audit-lab — Test IAM environment with known vulnerabilities"

Resources:
  # A service account with AdministratorAccess (the classic misconfiguration)
  DeployBot:
    Type: AWS::IAM::User
    Properties:
      UserName: lab-deploy-bot
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess

  # A human user without MFA
  InternUser:
    Type: AWS::IAM::User
    Properties:
      UserName: lab-intern-alice
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

  # An orphaned user (no policies, never activated)
  OrphanedUser:
    Type: AWS::IAM::User
    Properties:
      UserName: lab-orphaned-bob
```

Deploy:
```bash
aws cloudformation deploy \
  --template-file lab-01-setup.yaml \
  --stack-name iam-audit-lab-01 \
  --capabilities CAPABILITY_NAMED_IAM
```

---

## Exercise 1: Discover excessive permissions

Run the privilege analyzer:

```bash
k1n-iam-audit analyze-privileges --provider aws
```

**Questions:**
1. Which user has AdministratorAccess attached?
2. What is the risk score for this finding?
3. What severity was assigned, and why?

**Expected findings:**
- `[CRITICAL]` lab-deploy-bot — AdministratorAccess

---

## Exercise 2: Check MFA coverage

```bash
k1n-iam-audit analyze-mfa --provider aws
```

**Questions:**
1. What percentage of human accounts have MFA enabled?
2. Which users are missing MFA?
3. Which finding has the highest severity — and why?

**Expected findings:**
- `[HIGH]` lab-intern-alice — MFA not enabled

---

## Exercise 3: Find orphaned accounts

```bash
k1n-iam-audit analyze-inactive --provider aws --inactive-days 1
```

Using `--inactive-days 1` ensures the newly created accounts (with no activity) are flagged.

**Questions:**
1. Which accounts appear in the inactive/orphaned findings?
2. What remediation is suggested?

---

## Exercise 4: Generate a full report

```bash
k1n-iam-audit generate-report \
  --provider aws \
  --inactive-days 1 \
  --output ./output/lab01_report.md
```

Open `./output/lab01_report.md` and review:
1. The executive summary section
2. The full findings list
3. The identity inventory table

---

## Exercise 5: Remediate the critical finding

Replace the `AdministratorAccess` policy on `lab-deploy-bot` with a least-privilege policy.

Step 1 — Detach the overly permissive policy:
```bash
aws iam detach-user-policy \
  --user-name lab-deploy-bot \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Step 2 — Create and attach a least-privilege policy.
For this lab, assume `lab-deploy-bot` only needs to deploy Lambda functions:

```bash
aws iam create-policy \
  --policy-name lab-deploy-bot-policy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:GetFunction"
      ],
      "Resource": "arn:aws:lambda:us-east-1:*:function:lab-*"
    }]
  }'
```

Step 3 — Attach the new policy:
```bash
aws iam attach-user-policy \
  --user-name lab-deploy-bot \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/lab-deploy-bot-policy
```

Step 4 — Re-run the audit and verify the critical finding is gone:
```bash
k1n-iam-audit analyze-privileges --provider aws
```

---

## Cleanup

Delete the CloudFormation stack to remove all lab resources:
```bash
aws cloudformation delete-stack --stack-name iam-audit-lab-01
```

---

## Summary

In this lab you:
- Discovered a service account with AdministratorAccess (critical finding)
- Identified a human user without MFA (high finding)
- Found orphaned accounts (medium finding)
- Generated a full audit report
- Remediated the critical finding by applying a least-privilege policy

These are the three most common IAM security issues found in production cloud environments.
