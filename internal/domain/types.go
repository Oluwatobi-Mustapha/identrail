package domain

import "time"

// Provider identifies the source platform of identity and workload data.
type Provider string

const (
	ProviderAWS        Provider = "aws"
	ProviderKubernetes Provider = "kubernetes"
	ProviderAzure      Provider = "azure"
)

// IdentityType describes a machine identity category.
type IdentityType string

const (
	IdentityTypeRole           IdentityType = "role"
	IdentityTypeUser           IdentityType = "user"
	IdentityTypeServiceAccount IdentityType = "service_account"
	IdentityTypePrincipal      IdentityType = "principal"
)

// RelationshipType captures graph edge semantics used by path and blast radius analysis.
type RelationshipType string

const (
	RelationshipCanAssume      RelationshipType = "can_assume"
	RelationshipAttachedPolicy RelationshipType = "attached_policy"
	RelationshipBoundTo        RelationshipType = "bound_to"
	RelationshipCanAccess      RelationshipType = "can_access"
)

// FindingSeverity aligns risk scoring with operator expectations.
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

// FindingType keeps rule output strongly typed for filtering and remediation.
type FindingType string

const (
	FindingOverPrivileged   FindingType = "overprivileged_identity"
	FindingEscalationPath   FindingType = "escalation_path"
	FindingStaleIdentity    FindingType = "stale_identity"
	FindingOwnerless        FindingType = "ownerless_identity"
	FindingRiskyTrustPolicy FindingType = "risky_trust_policy"
)

// Identity is a normalized machine identity across providers.
type Identity struct {
	ID         string
	Provider   Provider
	Type       IdentityType
	Name       string
	ARN        string
	OwnerHint  string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	Tags       map[string]string
	RawRef     string
}

// Workload is a compute entity that can execute with one or more identities.
type Workload struct {
	ID        string
	Provider  Provider
	Type      string
	Name      string
	AccountID string
	Region    string
	RawRef    string
}

// Policy stores provider-native policy documents and parsed summaries.
type Policy struct {
	ID         string
	Provider   Provider
	Name       string
	Document   []byte
	Normalized map[string]any
	RawRef     string
}

// Relationship models directional edges in the permission graph.
type Relationship struct {
	ID           string
	Type         RelationshipType
	FromNodeID   string
	ToNodeID     string
	EvidenceRef  string
	DiscoveredAt time.Time
}

// Finding is a typed risk detected by the analysis engine.
type Finding struct {
	ID           string
	ScanID       string
	Type         FindingType
	Severity     FindingSeverity
	Title        string
	HumanSummary string
	Path         []string
	Evidence     map[string]any
	Remediation  string
	CreatedAt    time.Time
}

// OwnershipSignal tracks ownership hints and confidence.
type OwnershipSignal struct {
	ID         string
	IdentityID string
	Team       string
	Repository string
	Source     string
	Confidence float64
}

// Scan tracks one full ingestion and analysis run.
type Scan struct {
	ID         string
	Provider   Provider
	StartedAt  time.Time
	FinishedAt *time.Time
	Status     string
}
