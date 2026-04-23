from reports.markdown import generate_markdown_report
from schemas.models import AuditFinding


def test_findings_are_sorted_by_severity_then_provider_and_account():
    findings = [
        AuditFinding(
            title="low-aws-z",
            description="",
            severity="Low",
            provider="aws",
            account_id="z-account",
        ),
        AuditFinding(
            title="critical-gcp-a",
            description="",
            severity="Critical",
            provider="gcp",
            account_id="a-account",
        ),
        AuditFinding(
            title="high-aws-b",
            description="",
            severity="High",
            provider="aws",
            account_id="b-account",
        ),
        AuditFinding(
            title="high-aws-a",
            description="",
            severity="High",
            provider="aws",
            account_id="a-account",
        ),
        AuditFinding(
            title="medium-azure-a",
            description="",
            severity="Medium",
            provider="azure",
            account_id="a-account",
        ),
    ]

    report = generate_markdown_report([], findings)

    idx_critical = report.index("critical-gcp-a")
    idx_high_a = report.index("high-aws-a")
    idx_high_b = report.index("high-aws-b")
    idx_medium = report.index("medium-azure-a")
    idx_low = report.index("low-aws-z")

    assert idx_critical < idx_high_a < idx_high_b < idx_medium < idx_low
