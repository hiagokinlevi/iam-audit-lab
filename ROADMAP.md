# Roadmap

This document outlines the planned development trajectory for `iam-audit-lab`.

---

## v0.1 — Foundation (Current)

- [x] AWS IAM user and role collection
- [x] Azure AD user and service principal collection
- [x] GCP IAM member collection
- [x] Excessive permissions analyzer (detects wildcard/admin roles)
- [x] Inactive accounts analyzer (configurable threshold)
- [x] MFA coverage analyzer
- [x] Normalized IdentityRecord schema (Pydantic v2)
- [x] AuditFinding and RiskScore models
- [x] Markdown report generator (executive summary + full inventory)
- [x] Click CLI with all four commands
- [x] Offline AWS IAM policy analyzer CLI with CI threshold gating

---

## v0.2 — Deeper Analysis

- [ ] AWS: Detect unused IAM access keys (no use in N days)
- [ ] AWS: Identify roles with no trust policy referencing known services
- [x] AWS: Flag unrestricted `iam:PassRole` in exported IAM policy JSON
- [x] AWS: Flag accounts missing a strong password policy
- [ ] Azure: Detect guest users with privileged role assignments
- [ ] GCP: Detect projects with allUsers / allAuthenticatedUsers bindings
- [ ] Risk score aggregation (per account and per finding)

---

## v0.3 — Remediation Guidance

- [ ] Per-finding remediation steps (generated for each cloud provider)
- [ ] AWS: Generate least-privilege policy suggestions via IAM Access Analyzer integration
- [ ] Azure: Generate conditional access policy recommendations
- [ ] Export findings in SARIF format (compatible with GitHub Advanced Security)

---

## v0.4 — Compliance Mapping

- [ ] Map findings to CIS Benchmark controls (AWS, Azure, GCP)
- [ ] Map findings to NIST SP 800-53 controls
- [ ] Generate compliance gap report against a selected framework
- [ ] SOC 2 Type II evidence collection helpers

---

## v0.5 — Continuous Monitoring

- [ ] Scheduled audit runs via cron or cloud scheduler
- [ ] Delta reports: show only new findings since the last run
- [ ] Finding persistence (SQLite or JSON store for tracking over time)
- [ ] Alert on finding severity changes (e.g., new CRITICAL finding)

---

## v1.0 — Production Readiness

- [ ] Full test coverage (>90%)
- [ ] Comprehensive documentation site
- [ ] Performance optimization for large accounts (>1000 identities)
- [ ] Stable public API with semantic versioning guarantee

---

## Out of Scope (by design)

- **Remediation automation** — The tool identifies and reports findings. Remediation should be
  performed by authorized operators, not automated by an audit tool.
- **Attack simulation** — This is an audit tool, not a penetration testing framework.
- **Write access to any cloud provider** — All API access is strictly read-only.
