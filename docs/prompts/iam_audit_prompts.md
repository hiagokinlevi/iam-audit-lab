# IAM Audit Prompts

A curated collection of prompts for AI-assisted IAM security analysis. Use these with
an LLM to deepen your analysis of audit findings, generate remediation plans, and prepare
compliance documentation.

---

## Finding Analysis Prompts

### Explain an IAM finding in plain language

```
You are a cloud security engineer. Explain the following IAM audit finding to a non-technical
stakeholder in plain English. Focus on:
1. What the finding means
2. Why it is a security risk
3. What could happen if it is not fixed
4. How serious it is compared to other security issues

Finding:
<PASTE FINDING JSON HERE>
```

### Generate a remediation plan for a finding

```
You are a cloud security engineer. Create a detailed, step-by-step remediation plan for the
following IAM finding.

Provider: <aws|azure|gcp>
Finding: <PASTE FINDING DETAILS>

Include:
1. Immediate mitigation steps (to reduce risk while planning full remediation)
2. Long-term remediation steps (to fully resolve the issue)
3. Verification steps (how to confirm the issue is resolved)
4. Rollback plan (if the change causes unexpected issues)
5. Estimated effort (hours/days)
6. Any dependencies or prerequisites
```

### Prioritize a list of findings

```
You are a security engineer conducting a cloud IAM review. Given the following list of audit
findings, create a prioritized remediation roadmap.

Prioritize based on:
1. Blast radius (how much damage if exploited)
2. Likelihood of exploitation (is the identity externally accessible?)
3. Ease of remediation
4. Dependencies (some remediations may need to happen before others)

Findings:
<PASTE FINDINGS LIST>

Output a numbered list with your recommended remediation order and brief justification for
each priority decision.
```

---

## Policy Analysis Prompts

### Review an AWS IAM policy for excessive permissions

```
Review the following AWS IAM policy JSON for excessive permissions. Identify:
1. Actions that grant more access than a typical use case would require
2. Resources that should be scoped to specific ARNs instead of wildcards
3. Any actions that could be used for privilege escalation
4. A least-privilege rewrite of the policy

Policy:
<PASTE IAM POLICY JSON>

Context (what this policy is used for):
<DESCRIBE THE USE CASE>
```

### Generate a least-privilege IAM policy

```
Generate a least-privilege AWS IAM policy for the following use case. The policy should
grant only the permissions explicitly required and scope resources as narrowly as possible.

Use case: <DESCRIBE THE USE CASE>
Resources involved: <LIST ARNs OR RESOURCE TYPES>
Required operations: <LIST SPECIFIC ACTIONS>
Account ID: <AWS_ACCOUNT_ID>
Region: <REGION>

Return the policy as valid JSON with inline comments explaining each statement.
```

---

## Architecture Review Prompts

### Review IAM architecture for privilege escalation paths

```
Review the following IAM configuration for privilege escalation paths. A privilege escalation
path exists when a principal with limited permissions can take a series of allowed API calls
to ultimately obtain a higher level of access.

IAM configuration summary:
<DESCRIBE THE ROLES, POLICIES, AND TRUST RELATIONSHIPS>

Identify:
1. Direct escalation paths (single-hop)
2. Multi-hop escalation paths
3. Cross-account escalation risks
4. Recommendations to eliminate each path

Focus specifically on:
- iam:CreateAccessKey, iam:AttachUserPolicy, iam:PutUserPolicy
- sts:AssumeRole with permissive trust policies
- iam:PassRole abuse patterns
```

### Review MFA enforcement strategy

```
Review the following organization's MFA enforcement strategy for gaps and weaknesses.

Current strategy:
<DESCRIBE THE MFA POLICY AND ENFORCEMENT MECHANISM>

Evaluate against the following criteria:
1. Is MFA required for all human accounts, including break-glass accounts?
2. Is MFA enforced via policy or just recommended?
3. Are hardware security keys (FIDO2) required for privileged accounts?
4. What happens when a user loses their MFA device?
5. Are service accounts excluded appropriately?
6. How is MFA verified for API/programmatic access?

Provide a gap analysis and recommendations.
```

---

## Compliance Mapping Prompts

### Map findings to CIS Benchmark controls

```
Map the following IAM audit findings to the relevant CIS Benchmark controls for
<aws|azure|gcp>.

For each finding:
1. Identify the relevant CIS control number and description
2. Indicate whether the finding represents a compliance gap
3. Note any compensating controls that might satisfy the requirement

Findings:
<PASTE FINDINGS>
```

### Generate a SOC 2 compliance evidence summary

```
Generate a SOC 2 Type II evidence summary for the IAM audit results below.
Focus on the following SOC 2 criteria:
- CC6.1 (Logical and Physical Access Controls)
- CC6.2 (Provisioning and Deprovisioning)
- CC6.3 (Role-Based Access)
- CC9.2 (Service Provider Monitoring)

Audit results:
<PASTE AUDIT SUMMARY>

Format the output as a table mapping each finding to the relevant SOC 2 criterion,
with a status of PASS, FAIL, or PARTIAL.
```
