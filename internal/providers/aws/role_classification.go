package aws

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

const (
	identrailConnectorRoleName = "IdentrailReadOnly"
	awsFindingProvenance       = "aws_iam_inventory"
	awsFindingAdapterSource    = "aws_iam_rule_engine"
	awsFindingEvidenceVersion  = "aws-finding-v2"
)

type serviceLinkedRoleExpectation struct {
	RoleName         string
	ServicePrincipal string
}

var expectedServiceLinkedRoles = map[string]serviceLinkedRoleExpectation{
	"awsserviceroleforamazonsecuritylake": {
		RoleName:         "AWSServiceRoleForAmazonSecurityLake",
		ServicePrincipal: "securitylake.amazonaws.com",
	},
	"awsserviceroleforsupport": {
		RoleName:         "AWSServiceRoleForSupport",
		ServicePrincipal: "support.amazonaws.com",
	},
	"awsservicerolefortrustedadvisor": {
		RoleName:         "AWSServiceRoleForTrustedAdvisor",
		ServicePrincipal: "trustedadvisor.amazonaws.com",
	},
	"awsservicerolefororganizations": {
		RoleName:         "AWSServiceRoleForOrganizations",
		ServicePrincipal: "organizations.amazonaws.com",
	},
}

// ConnectorRoleExpectation is the live connector contract used to distinguish
// expected cross-account trust from actual trust drift. ExternalID is compared
// in memory and is never copied into finding evidence.
type ConnectorRoleExpectation struct {
	RoleARN          string
	AccountID        string
	TrustedAccountID string
	ExternalID       string
}

func classifyIAMRoleIdentity(role IAMRole) (domain.IdentityKind, domain.IdentityManagedBy, domain.FindingActionability) {
	name := strings.TrimSpace(role.Name)
	if isIdentrailConnectorRole(name, role.Tags) {
		return domain.IdentityKindConnector, domain.IdentityManagedByIdentrail, domain.FindingActionabilityReview
	}
	if strings.HasPrefix(strings.ToLower(name), "awsservicerolefor") || strings.Contains(strings.ToLower(strings.TrimSpace(role.Path)), "/aws-service-role/") {
		return domain.IdentityKindServiceLinked, domain.IdentityManagedByAWSService, domain.FindingActionabilityObserveOnly
	}
	return domain.IdentityKindStandard, domain.IdentityManagedByCustomer, domain.FindingActionabilityActionRequired
}

func isIdentrailConnectorRole(name string, tags map[string]string) bool {
	if strings.EqualFold(strings.TrimSpace(name), identrailConnectorRoleName) {
		return true
	}
	for key := range tags {
		if strings.EqualFold(strings.TrimSpace(key), "IdentrailConnectorMode") {
			return true
		}
	}
	return false
}

func expectedServiceLinkedRole(identity domain.Identity) (serviceLinkedRoleExpectation, bool) {
	expectation, ok := expectedServiceLinkedRoles[strings.ToLower(strings.TrimSpace(identity.Name))]
	return expectation, ok
}

func isExpectedAWSManagedPolicyARN(policyARN string) bool {
	parts := strings.Split(strings.TrimSpace(policyARN), ":")
	return len(parts) >= 6 && parts[2] == "iam" && parts[4] == "aws" && strings.HasPrefix(strings.ToLower(parts[5]), "policy/aws-service-role/")
}

func permissionPoliciesForIdentity(bundle providers.NormalizedBundle, identityID string) []domain.Policy {
	policies := make([]domain.Policy, 0)
	for _, policy := range bundle.Policies {
		policyType, _ := policy.Normalized[policyTypeKey].(string)
		policyIdentityID, _ := policy.Normalized[identityIDKey].(string)
		if policyType == policyTypePerm && policyIdentityID == identityID {
			policies = append(policies, policy)
		}
	}
	return policies
}

func trustPolicyForIdentity(bundle providers.NormalizedBundle, identityID string) *domain.Policy {
	for i := range bundle.Policies {
		policy := &bundle.Policies[i]
		policyType, _ := policy.Normalized[policyTypeKey].(string)
		policyIdentityID, _ := policy.Normalized[identityIDKey].(string)
		if policyType == policyTypeTrust && policyIdentityID == identityID {
			return policy
		}
	}
	return nil
}

type trustPolicyFacts struct {
	AWSPrincipals     []string
	ServicePrincipals []string
	OtherPrincipals   []string
	ExternalIDs       []string
	AllowsAssumeRole  bool
}

func inspectTrustPolicy(policy *domain.Policy) trustPolicyFacts {
	if policy == nil {
		return trustPolicyFacts{}
	}
	doc, err := parsePolicyDocument(string(policy.Document))
	if err != nil {
		return trustPolicyFacts{}
	}
	facts := trustPolicyFacts{}
	for _, statement := range doc.Statement {
		if !strings.EqualFold(strings.TrimSpace(statement.Effect), "allow") {
			continue
		}
		for _, action := range parseStringList(statement.Action) {
			if strings.EqualFold(strings.TrimSpace(action), "sts:AssumeRole") {
				facts.AllowsAssumeRole = true
			}
		}
		facts.AWSPrincipals = append(facts.AWSPrincipals, parseAWSPrincipals(statement.Principal)...)
		facts.ServicePrincipals = append(facts.ServicePrincipals, parsePrincipalType(statement.Principal, "Service")...)
		facts.OtherPrincipals = append(facts.OtherPrincipals, parsePrincipalType(statement.Principal, "Federated")...)
		facts.OtherPrincipals = append(facts.OtherPrincipals, parsePrincipalType(statement.Principal, "CanonicalUser")...)
		facts.ExternalIDs = append(facts.ExternalIDs, conditionValues(statement.Condition, "sts:ExternalId")...)
	}
	facts.AWSPrincipals = sortedUniqueStrings(facts.AWSPrincipals)
	facts.ServicePrincipals = sortedUniqueStrings(facts.ServicePrincipals)
	facts.OtherPrincipals = sortedUniqueStrings(facts.OtherPrincipals)
	facts.ExternalIDs = sortedUniqueStrings(facts.ExternalIDs)
	return facts
}

func conditionValues(condition map[string]any, wantedKey string) []string {
	values := []string{}
	for _, operatorValue := range condition {
		operatorMap, ok := operatorValue.(map[string]any)
		if !ok {
			continue
		}
		for key, value := range operatorMap {
			if strings.EqualFold(strings.TrimSpace(key), wantedKey) {
				values = append(values, parseStringList(value)...)
			}
		}
	}
	return sortedUniqueStrings(values)
}

func sortedUniqueStrings(values []string) []string {
	values = dedupeStrings(values)
	sort.Strings(values)
	return values
}

func expectedServiceLinkedRoleSignals(bundle providers.NormalizedBundle, identity domain.Identity, expectation serviceLinkedRoleExpectation, hasBroadAccess bool) []string {
	signals := []string{}
	facts := inspectTrustPolicy(trustPolicyForIdentity(bundle, identity.ID))
	if !facts.AllowsAssumeRole || len(facts.ServicePrincipals) != 1 || !strings.EqualFold(facts.ServicePrincipals[0], expectation.ServicePrincipal) || len(facts.AWSPrincipals) > 0 || len(facts.OtherPrincipals) > 0 {
		signals = append(signals, "unexpected_trust")
	}
	customerPolicy := false
	for _, policy := range permissionPoliciesForIdentity(bundle, identity.ID) {
		policyARN, _ := policy.Normalized[policyARNKey].(string)
		attachmentType, _ := policy.Normalized[attachmentTypeKey].(string)
		if !isExpectedAWSManagedPolicyARN(policyARN) || !strings.EqualFold(strings.TrimSpace(attachmentType), "managed") {
			customerPolicy = true
			break
		}
	}
	if customerPolicy {
		signals = append(signals, "customer_added_policy")
		if hasBroadAccess {
			signals = append(signals, "unexpected_permission_reachability")
		}
	}
	return sortedUniqueStrings(signals)
}

func connectorRoleSignals(bundle providers.NormalizedBundle, identity domain.Identity, expectation ConnectorRoleExpectation) (signals []string, completeness string) {
	completeness = "complete"
	if expectedARN := strings.TrimSpace(expectation.RoleARN); expectedARN != "" && !strings.EqualFold(strings.TrimSpace(identity.ARN), expectedARN) {
		signals = append(signals, "connector_role_mismatch")
	}
	if expectedAccount := strings.TrimSpace(expectation.AccountID); expectedAccount != "" && accountIDFromARN(identity.ARN) != expectedAccount {
		signals = append(signals, "connector_account_mismatch")
	}

	policy := trustPolicyForIdentity(bundle, identity.ID)
	facts := inspectTrustPolicy(policy)
	if policy == nil {
		completeness = "partial"
		signals = append(signals, "trust_evidence_missing")
	} else {
		expectedTrustedAccount := strings.TrimSpace(expectation.TrustedAccountID)
		if expectedTrustedAccount == "" {
			completeness = "partial"
			signals = append(signals, "trusted_account_expectation_missing")
		} else if !facts.AllowsAssumeRole || len(facts.AWSPrincipals) != 1 || accountIDFromPrincipal(facts.AWSPrincipals[0]) != expectedTrustedAccount || len(facts.ServicePrincipals) > 0 || len(facts.OtherPrincipals) > 0 {
			signals = append(signals, "unexpected_trust")
		}

		expectedExternalID := strings.TrimSpace(expectation.ExternalID)
		if expectedExternalID == "" {
			completeness = "partial"
			signals = append(signals, "external_id_expectation_missing")
		} else if len(facts.ExternalIDs) != 1 || facts.ExternalIDs[0] != expectedExternalID {
			signals = append(signals, "external_id_mismatch")
		}
	}

	permissionPolicies := permissionPoliciesForIdentity(bundle, identity.ID)
	if len(permissionPolicies) == 0 {
		completeness = "partial"
		signals = append(signals, "permission_evidence_missing")
	} else if connectorPermissionScopeExpanded(permissionPolicies) {
		signals = append(signals, "permission_scope_expanded")
	}
	return sortedUniqueStrings(signals), completeness
}

func connectorPermissionScopeExpanded(policies []domain.Policy) bool {
	for _, policy := range policies {
		statements, err := parseNormalizedStatements(policy.Normalized[statementsKey])
		if err != nil {
			return true
		}
		for _, statement := range statements {
			effect, _ := statement["effect"].(string)
			if !strings.EqualFold(effect, "Allow") {
				continue
			}
			for _, action := range parseStringList(statement["actions"]) {
				if !isConnectorReadOnlyAction(action) {
					return true
				}
			}
		}
	}
	return false
}

func isConnectorReadOnlyAction(action string) bool {
	action = strings.TrimSpace(action)
	parts := strings.SplitN(action, ":", 2)
	if len(parts) != 2 || strings.Contains(parts[1], "*") {
		return false
	}
	operation := strings.ToLower(parts[1])
	for _, prefix := range []string{"get", "list", "describe", "batchget", "lookup", "search", "simulate"} {
		if strings.HasPrefix(operation, prefix) {
			return true
		}
	}
	return strings.EqualFold(action, "iam:GenerateServiceLastAccessedDetails")
}

func managedRoleAnomalyFinding(identity domain.Identity, expectation serviceLinkedRoleExpectation, signals []string, now time.Time) domain.Finding {
	finding := domain.Finding{
		ID:                   findingID(domain.FindingRiskyTrustPolicy, identity.ID, strings.Join(signals, ",")),
		Type:                 domain.FindingRiskyTrustPolicy,
		Severity:             domain.SeverityHigh,
		ConfidenceScore:      0.95,
		Actionability:        domain.FindingActionabilityReview,
		Exploitability:       domain.FindingExploitabilityPlausible,
		EvidenceCompleteness: "complete",
		Provenance:           awsFindingProvenance,
		Title:                fmt.Sprintf("AWS-managed role anomaly: %s", displayIdentity(identity)),
		HumanSummary:         "This expected AWS service-linked role differs from its managed trust or policy boundary and needs investigation without directly editing the role.",
		Path:                 []string{identity.ID},
		Evidence: map[string]any{
			"identity_id":                identity.ID,
			"identity_arn":               identity.ARN,
			"expected_service_principal": expectation.ServicePrincipal,
			"contributing_signals":       signals,
		},
		Remediation: "Review the owning AWS service configuration and CloudTrail history. Restore the service-linked role through the AWS service workflow instead of editing it directly.",
		CreatedAt:   now,
	}
	decorateAWSFinding(&finding, identity, signals, now)
	return finding
}

func connectorTrustReviewFinding(identity domain.Identity, signals []string, completeness string, now time.Time) domain.Finding {
	actionability := domain.FindingActionabilityObserveOnly
	severity := domain.SeverityInfo
	exploitability := domain.FindingExploitabilityNone
	title := fmt.Sprintf("Connector trust review: %s", displayIdentity(identity))
	summary := "The Identrail connector role matches the expected account, external-ID trust condition, and read-only permission boundary."
	remediation := "No direct AWS change is recommended. Continue monitoring the connector trust and read-only policy for drift."
	invalid := false
	for _, signal := range signals {
		if !strings.HasSuffix(signal, "_missing") {
			invalid = true
			break
		}
	}
	if invalid {
		actionability = domain.FindingActionabilityActionRequired
		severity = domain.SeverityHigh
		exploitability = domain.FindingExploitabilityPlausible
		title = fmt.Sprintf("Connector role configuration drift: %s", displayIdentity(identity))
		summary = "The Identrail connector role no longer matches its expected account, external-ID trust, or read-only permission boundary."
		remediation = "Restore the connector trust and collector policy from the Identrail onboarding template. Do not add permissions or weaken the external-ID condition."
	} else if len(signals) > 0 {
		actionability = domain.FindingActionabilityReview
		exploitability = domain.FindingExploitabilityUnknown
		summary = "The role is recognized as the Identrail connector, but available evidence is insufficient to prove that every trust and read-only policy invariant still matches."
		remediation = "Refresh connector validation and the IAM policy inventory before treating the role as safe."
	}
	confidence := 0.95
	if !invalid && completeness != "complete" {
		confidence = 0.72
	}
	finding := domain.Finding{
		ID:                   findingID(domain.FindingRiskyTrustPolicy, identity.ID, "connector-review|"+strings.Join(signals, ",")),
		Type:                 domain.FindingRiskyTrustPolicy,
		Severity:             severity,
		ConfidenceScore:      confidence,
		Actionability:        actionability,
		Exploitability:       exploitability,
		EvidenceCompleteness: completeness,
		Provenance:           awsFindingProvenance,
		Title:                title,
		HumanSummary:         summary,
		Path:                 []string{identity.ID},
		Evidence: map[string]any{
			"identity_id":                 identity.ID,
			"identity_arn":                identity.ARN,
			"external_id_condition_valid": !stringSliceContains(signals, "external_id_expectation_missing") && !stringSliceContains(signals, "external_id_mismatch"),
			"contributing_signals":        signals,
		},
		Remediation: remediation,
		CreatedAt:   now,
	}
	decorateAWSFinding(&finding, identity, signals, now)
	return finding
}

func stringSliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func decorateAWSFinding(finding *domain.Finding, identity domain.Identity, signals []string, now time.Time) {
	if finding == nil {
		return
	}
	if finding.ConfidenceScore == 0 {
		finding.ConfidenceScore = 0.9
	}
	if finding.Actionability == "" {
		finding.Actionability = domain.FindingActionabilityActionRequired
	}
	if finding.Exploitability == "" {
		finding.Exploitability = domain.FindingExploitabilityUnknown
	}
	if finding.EvidenceCompleteness == "" {
		finding.EvidenceCompleteness = "complete"
	}
	if finding.Provenance == "" {
		finding.Provenance = awsFindingProvenance
	}
	finding.AdapterSource = awsFindingAdapterSource
	finding.ConfidenceState = "inventory_backed"
	finding.EvidenceVersion = awsFindingEvidenceVersion
	if finding.Evidence == nil {
		finding.Evidence = map[string]any{}
	}
	identityKind := identity.IdentityKind
	if identityKind == "" {
		identityKind = domain.IdentityKindStandard
	}
	managedBy := identity.ManagedBy
	if managedBy == "" {
		managedBy = domain.IdentityManagedByCustomer
	}
	finding.Evidence["account_id"] = accountIDFromARN(identity.ARN)
	finding.Evidence["region"] = "global"
	finding.Evidence["source"] = awsFindingAdapterSource
	finding.Evidence["observed_at"] = now.Format(time.RFC3339)
	finding.Evidence["provenance"] = finding.Provenance
	finding.Evidence["confidence"] = finding.ConfidenceScore
	finding.Evidence["identity_kind"] = identityKind
	finding.Evidence["managed_by"] = managedBy
	finding.Evidence["actionability"] = finding.Actionability
	finding.Evidence["exploitability"] = finding.Exploitability
	finding.Evidence["evidence_completeness"] = finding.EvidenceCompleteness
	finding.Evidence["evidence_boundary"] = "IAM role inventory, trust policy, and collected permission policies"
	if len(signals) > 0 {
		finding.Evidence["contributing_signals"] = sortedUniqueStrings(signals)
	}
}
