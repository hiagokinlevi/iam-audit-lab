"""
IAM Identity and Finding Schemas
==================================
Pydantic v2 models for normalized IAM identity records, audit findings,
and risk scores.

These schemas provide a common representation across all cloud providers,
allowing analyzers and report generators to work with a single data model
regardless of the underlying provider.

Design notes:
- All datetime fields are stored as ISO 8601 strings to avoid timezone
  complexity across different provider SDK formats.
- Optional fields default to None rather than empty strings to distinguish
  "not provided" from "empty".
- IdentityType uses a closed enum to prevent unexpected values propagating
  through the analysis pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class IdentityType(str, Enum):
    """Classification of an IAM identity."""

    HUMAN = "human"          # A person (employee, contractor, external user)
    SERVICE = "service"      # A service account, managed identity, or application
    GROUP = "group"          # A group or role that aggregates other identities
    UNKNOWN = "unknown"      # Type could not be determined


class IdentityStatus(str, Enum):
    """Activity status of an identity."""

    ACTIVE = "active"
    INACTIVE = "inactive"    # No activity within the configured threshold
    DISABLED = "disabled"    # Explicitly disabled by an administrator
    UNKNOWN = "unknown"


class FindingSeverity(str, Enum):
    """Severity classification for audit findings."""

    CRITICAL = "critical"    # Immediate remediation required
    HIGH = "high"            # Remediate in the next sprint
    MEDIUM = "medium"        # Remediate in the next quarter
    LOW = "low"              # Track but no immediate action required
    INFORMATIONAL = "informational"  # Observation only


class FindingCategory(str, Enum):
    """Category of an audit finding."""

    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    INACTIVE_ACCOUNT = "inactive_account"
    MFA_NOT_ENABLED = "mfa_not_enabled"
    ORPHANED_ACCOUNT = "orphaned_account"
    PRIVILEGED_WITHOUT_MFA = "privileged_without_mfa"
    CREDENTIAL_ROTATION = "credential_rotation"
    OVER_PRIVILEGED_ROLE = "over_privileged_role"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Identity record
# ---------------------------------------------------------------------------


class IdentityRecord(BaseModel):
    """
    Normalized representation of a cloud IAM identity.

    This model is populated by provider-specific collectors and consumed
    by analyzers and the report generator. Fields that are not available
    for a given provider are set to None.
    """

    # Core identity fields
    identity_id: str = Field(description="Provider-assigned unique ID (e.g., AWS UserId).")
    identity_name: str = Field(description="Human-readable name (username, display name, etc.).")
    identity_type: IdentityType = Field(description="Type classification of this identity.")
    provider: str = Field(description="Cloud provider: aws, azure, gcp, or entra.")
    status: IdentityStatus = Field(
        default=IdentityStatus.UNKNOWN,
        description="Current status of the identity.",
    )

    # Activity tracking
    created_at: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp when the identity was created.",
    )
    last_activity_at: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp of the last recorded activity. "
                    "'never' indicates the account has never been used.",
    )

    # Security attributes
    mfa_enabled: bool = Field(
        default=False,
        description="Whether MFA is enabled for this identity. "
                    "Always False for service accounts (not applicable).",
    )
    attached_policies: list[str] = Field(
        default_factory=list,
        description="Names of directly attached policies or roles.",
    )
    is_privileged: bool = Field(
        default=False,
        description="Whether this identity has been identified as privileged "
                    "(admin-level or broad permissions).",
    )

    # Provider-specific metadata
    arn: Optional[str] = Field(None, description="AWS ARN, Azure object ID, or GCP member string.")
    tags: dict[str, str] = Field(
        default_factory=dict,
        description="Provider tags or labels attached to this identity.",
    )
    raw_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Provider-specific fields that do not map to the normalized schema. "
                    "Useful for debugging but should not be relied upon by analyzers.",
    )

    model_config = {"json_schema_extra": {
        "example": {
            "identity_id": "AIDAEXAMPLE123456789",
            "identity_name": "deploy-bot",
            "identity_type": "service",
            "provider": "aws",
            "status": "active",
            "created_at": "2023-06-15T10:30:00Z",
            "last_activity_at": "2025-01-10T08:45:00Z",
            "mfa_enabled": False,
            "attached_policies": ["AdministratorAccess"],
            "is_privileged": True,
            "arn": "arn:aws:iam::123456789012:user/deploy-bot",
        }
    }}


# ---------------------------------------------------------------------------
# Audit finding
# ---------------------------------------------------------------------------


class AuditFinding(BaseModel):
    """
    A single finding produced by an analyzer.

    Findings represent specific security issues associated with one or more
    IAM identities. Each finding includes remediation guidance specific to
    the provider and finding type.
    """

    # Finding identity
    finding_id: str = Field(
        default_factory=lambda: uuid4().hex[:12],
        description="Unique identifier for this finding.",
    )
    category: FindingCategory
    severity: FindingSeverity
    provider: str = Field(description="Cloud provider this finding applies to.")

    # Associated identity
    identity_id: str = Field(description="ID of the identity this finding is about.")
    identity_name: str = Field(description="Name of the identity for readability.")

    # Finding details
    title: str = Field(description="Short, descriptive title of the finding.")
    description: str = Field(description="Detailed explanation of the finding and its risk.")
    evidence: list[str] = Field(
        default_factory=list,
        description="Specific evidence supporting the finding (policy names, last activity, etc.).",
    )
    remediation: str = Field(
        default="",
        description="Recommended remediation steps.",
    )

    # Risk score
    risk_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Normalized risk score for this finding (0.0 = low, 1.0 = critical).",
    )

    # Timestamps
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this finding was detected.",
    )


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------


class RiskScore(BaseModel):
    """
    Aggregated risk score for an IAM identity.

    Combines findings from multiple analyzers into a single risk profile.
    """

    identity_id: str
    identity_name: str
    provider: str

    # Component scores from each analyzer
    privilege_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Risk contribution from permission level.",
    )
    inactivity_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Risk contribution from account inactivity.",
    )
    mfa_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Risk contribution from missing MFA.",
    )

    # Aggregated score
    overall_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Weighted aggregate risk score.",
    )
    severity: FindingSeverity = Field(
        default=FindingSeverity.INFORMATIONAL,
        description="Overall severity derived from the aggregate score.",
    )

    # Supporting findings
    finding_ids: list[str] = Field(
        default_factory=list,
        description="IDs of findings that contributed to this risk score.",
    )

    @field_validator("overall_score")
    @classmethod
    def round_score(cls, v: float) -> float:
        return round(v, 4)

    def compute_overall(
        self,
        privilege_weight: float = 0.4,
        inactivity_weight: float = 0.3,
        mfa_weight: float = 0.3,
    ) -> "RiskScore":
        """
        Recompute the overall score using the provided weights.

        Weights should sum to 1.0. Returns self for chaining.
        """
        self.overall_score = min(1.0, round(
            self.privilege_score * privilege_weight
            + self.inactivity_score * inactivity_weight
            + self.mfa_score * mfa_weight,
            4,
        ))
        # Map overall score to severity
        if self.overall_score >= 0.8:
            self.severity = FindingSeverity.CRITICAL
        elif self.overall_score >= 0.6:
            self.severity = FindingSeverity.HIGH
        elif self.overall_score >= 0.4:
            self.severity = FindingSeverity.MEDIUM
        elif self.overall_score >= 0.2:
            self.severity = FindingSeverity.LOW
        else:
            self.severity = FindingSeverity.INFORMATIONAL

        return self
