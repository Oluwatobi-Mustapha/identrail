package aws

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

func TestRuleSetDetectsAllPrimaryRiskTypes(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	lastUsed := now.Add(-120 * 24 * time.Hour)
	identity := domain.Identity{
		ID:         identityIDFromARN("arn:aws:iam::123456789012:role/admin-app"),
		Provider:   domain.ProviderAWS,
		Type:       domain.IdentityTypeRole,
		Name:       "admin-app",
		ARN:        "arn:aws:iam::123456789012:role/admin-app",
		CreatedAt:  now.Add(-400 * 24 * time.Hour),
		LastUsedAt: &lastUsed,
	}

	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}
	relationships := []domain.Relationship{
		{Type: domain.RelationshipCanAssume, FromNodeID: "aws:principal:*", ToNodeID: identity.ID},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("iam:*", "*")},
	}

	rules := NewRuleSet(WithRuleClock(func() time.Time { return now }))
	findings, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}

	types := map[domain.FindingType]bool{}
	for _, finding := range findings {
		types[finding.Type] = true
	}

	expected := []domain.FindingType{
		domain.FindingOwnerless,
		domain.FindingStaleIdentity,
		domain.FindingOverPrivileged,
		domain.FindingRiskyTrustPolicy,
		domain.FindingEscalationPath,
	}
	for _, findingType := range expected {
		if !types[findingType] {
			t.Fatalf("expected finding type %s", findingType)
		}
	}
}

func TestRuleSetFixturePipelineDetectsCrossAccountTrust(t *testing.T) {
	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{loadRawRoleAssetFixture(t, "role_with_policies.json")})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	permissions, err := NewPolicyPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions failed: %v", err)
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, permissions)
	if err != nil {
		t.Fatalf("resolve relationships failed: %v", err)
	}

	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	findings, err := NewRuleSet(WithRuleClock(func() time.Time { return now })).Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}

	if !containsFindingType(findings, domain.FindingRiskyTrustPolicy) {
		t.Fatalf("expected risky trust finding, got %+v", findingTypes(findings))
	}
	if containsFindingType(findings, domain.FindingOverPrivileged) {
		t.Fatalf("did not expect overprivileged finding for fixture role")
	}
}

func TestRuleSetContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewRuleSet().Evaluate(ctx, providers.NormalizedBundle{}, nil)
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestRuleSetDeterministicIDs(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:       identityIDFromARN("arn:aws:iam::123456789012:role/demo"),
		Provider: domain.ProviderAWS,
		Type:     domain.IdentityTypeRole,
		ARN:      "arn:aws:iam::123456789012:role/demo",
		Name:     "demo",
	}
	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}
	relationships := []domain.Relationship{{
		Type:       domain.RelationshipCanAccess,
		FromNodeID: identity.ID,
		ToNodeID:   accessNodeID("iam:*", "*"),
	}}

	rules := NewRuleSet(WithRuleClock(func() time.Time { return now }))
	first, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("first evaluate failed: %v", err)
	}
	second, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("second evaluate failed: %v", err)
	}

	if len(first) != len(second) {
		t.Fatalf("finding counts differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatalf("non-deterministic ID at index %d: %s vs %s", i, first[i].ID, second[i].ID)
		}
	}
}

func TestRuleSetDeterministicEvidenceOrdering(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:       identityIDFromARN("arn:aws:iam::123456789012:role/demo"),
		Provider: domain.ProviderAWS,
		Type:     domain.IdentityTypeRole,
		ARN:      "arn:aws:iam::123456789012:role/demo",
		Name:     "demo",
	}
	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}

	relationshipsA := []domain.Relationship{
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("iam:PassRole", "*")},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("ec2:*", "*")},
		{Type: domain.RelationshipCanAssume, FromNodeID: "aws:principal:*", ToNodeID: identity.ID},
	}
	relationshipsB := []domain.Relationship{
		{Type: domain.RelationshipCanAssume, FromNodeID: "aws:principal:*", ToNodeID: identity.ID},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("ec2:*", "*")},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("iam:PassRole", "*")},
	}

	rules := NewRuleSet(WithRuleClock(func() time.Time { return now }))
	findingsA, err := rules.Evaluate(context.Background(), bundle, relationshipsA)
	if err != nil {
		t.Fatalf("evaluate A failed: %v", err)
	}
	findingsB, err := rules.Evaluate(context.Background(), bundle, relationshipsB)
	if err != nil {
		t.Fatalf("evaluate B failed: %v", err)
	}

	var overA, overB domain.Finding
	for _, finding := range findingsA {
		if finding.Type == domain.FindingOverPrivileged {
			overA = finding
			break
		}
	}
	for _, finding := range findingsB {
		if finding.Type == domain.FindingOverPrivileged {
			overB = finding
			break
		}
	}
	if overA.ID == "" || overB.ID == "" {
		t.Fatalf("missing overprivileged finding; got A=%v B=%v", findingTypes(findingsA), findingTypes(findingsB))
	}
	if !reflect.DeepEqual(overA.Evidence, overB.Evidence) {
		t.Fatalf("expected deterministic evidence ordering, got A=%+v B=%+v", overA.Evidence, overB.Evidence)
	}
}

func TestRuleSetDeterministicAcrossShuffledRelationshipInput(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 30, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:       identityIDFromARN("arn:aws:iam::123456789012:role/demo"),
		Provider: domain.ProviderAWS,
		Type:     domain.IdentityTypeRole,
		ARN:      "arn:aws:iam::123456789012:role/demo",
		Name:     "demo",
	}
	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}

	relationshipA := domain.Relationship{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("iam:PassRole", "*")}
	relationshipB := domain.Relationship{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("ec2:*", "*")}
	relationshipC := domain.Relationship{Type: domain.RelationshipCanAssume, FromNodeID: "aws:principal:*", ToNodeID: identity.ID}
	orders := [][]domain.Relationship{
		{relationshipA, relationshipB, relationshipC},
		{relationshipC, relationshipA, relationshipB},
		{relationshipB, relationshipC, relationshipA},
	}

	rules := NewRuleSet(WithRuleClock(func() time.Time { return now }))
	var baseline []string
	for idx, relationships := range orders {
		findings, err := rules.Evaluate(context.Background(), bundle, relationships)
		if err != nil {
			t.Fatalf("evaluate shuffled relationships %d failed: %v", idx, err)
		}
		signature := make([]string, 0, len(findings))
		for _, finding := range findings {
			payload, err := json.Marshal(finding.Evidence)
			if err != nil {
				t.Fatalf("marshal evidence for finding %s: %v", finding.ID, err)
			}
			signature = append(signature, finding.ID+"|"+string(finding.Type)+"|"+string(finding.Severity)+"|"+string(payload))
		}
		if idx == 0 {
			baseline = signature
			continue
		}
		if !reflect.DeepEqual(baseline, signature) {
			t.Fatalf("expected deterministic findings for shuffled relationship input, baseline=%+v got=%+v", baseline, signature)
		}
	}
}

func TestParseAccessNode(t *testing.T) {
	action, resource, ok := parseAccessNode(accessNodeID("s3:GetObject", "arn:aws:s3:::bucket/*"))
	if !ok {
		t.Fatal("expected parse success")
	}
	if action != "s3:GetObject" || resource != "arn:aws:s3:::bucket/*" {
		t.Fatalf("unexpected parse values: %q %q", action, resource)
	}
}

func TestAccountIDFromARN(t *testing.T) {
	if got := accountIDFromARN("arn:aws:iam::123456789012:role/demo"); got != "123456789012" {
		t.Fatalf("unexpected account id: %q", got)
	}
	if got := accountIDFromARN("invalid"); got != "" {
		t.Fatalf("expected empty account id, got %q", got)
	}
}

func TestAccountIDFromPrincipal(t *testing.T) {
	tests := []struct {
		name      string
		principal string
		want      string
	}{
		{name: "full arn", principal: "arn:aws:iam::123456789012:role/demo", want: "123456789012"},
		{name: "bare account id", principal: "999999999999", want: "999999999999"},
		{name: "padded bare account id", principal: " 999999999999 ", want: "999999999999"},
		{name: "non-numeric 12 chars falls back to arn", principal: "abcdefghijkl", want: ""},
		{name: "wildcard", principal: "*", want: ""},
		{name: "empty", principal: "", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := accountIDFromPrincipal(tc.principal); got != tc.want {
				t.Fatalf("accountIDFromPrincipal(%q) = %q, want %q", tc.principal, got, tc.want)
			}
		})
	}
}

func TestSeveritySortOrder(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:       identityIDFromARN("arn:aws:iam::123456789012:role/admin-app"),
		Provider: domain.ProviderAWS,
		Type:     domain.IdentityTypeRole,
		ARN:      "arn:aws:iam::123456789012:role/admin-app",
		Name:     "admin-app",
	}

	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}
	relationships := []domain.Relationship{
		{Type: domain.RelationshipCanAssume, FromNodeID: "aws:principal:*", ToNodeID: identity.ID},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("iam:*", "*")},
	}

	findings, err := NewRuleSet(WithRuleClock(func() time.Time { return now })).Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected multiple findings, got %d", len(findings))
	}

	severities := make([]domain.FindingSeverity, 0, len(findings))
	for _, finding := range findings {
		severities = append(severities, finding.Severity)
	}
	criticalIndex := slices.Index(severities, domain.SeverityCritical)
	highIndex := slices.Index(severities, domain.SeverityHigh)
	if criticalIndex == -1 || highIndex == -1 || criticalIndex > highIndex {
		t.Fatalf("expected critical findings before high findings, got order %+v", severities)
	}
}

func TestRuleSetSuppressesDefaultNoiseForExpectedServiceLinkedRoles(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name             string
		roleName         string
		servicePrincipal string
	}{
		{name: "Security Lake", roleName: "AWSServiceRoleForAmazonSecurityLake", servicePrincipal: "securitylake.amazonaws.com"},
		{name: "Support", roleName: "AWSServiceRoleForSupport", servicePrincipal: "support.amazonaws.com"},
		{name: "Trusted Advisor", roleName: "AWSServiceRoleForTrustedAdvisor", servicePrincipal: "trustedadvisor.amazonaws.com"},
		{name: "Organizations", roleName: "AWSServiceRoleForOrganizations", servicePrincipal: "organizations.amazonaws.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			role := IAMRole{
				ARN:                      "arn:aws:iam::123456789012:role/aws-service-role/" + tc.servicePrincipal + "/" + tc.roleName,
				Name:                     tc.roleName,
				Path:                     "/aws-service-role/" + tc.servicePrincipal + "/",
				CreatedAt:                timePointer(now.Add(-400 * 24 * time.Hour)),
				AssumeRolePolicyDocument: trustPolicyJSON(map[string]any{"Service": tc.servicePrincipal}, ""),
				PermissionPolicies: []IAMPermissionPolicy{{
					Name:           tc.roleName + "Policy",
					ARN:            "arn:aws:iam::aws:policy/aws-service-role/" + tc.roleName + "Policy",
					AttachmentType: "managed",
					Document:       `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"organizations:*","Resource":"*"}}`,
				}},
			}
			bundle, relationships := normalizeRoleForRuleTest(t, role)
			identity := bundle.Identities[0]
			if identity.IdentityKind != domain.IdentityKindServiceLinked || identity.ManagedBy != domain.IdentityManagedByAWSService || identity.Actionability != domain.FindingActionabilityObserveOnly {
				t.Fatalf("unexpected service-linked classification: %+v", identity)
			}
			findings, err := NewRuleSet(WithRuleClock(func() time.Time { return now })).Evaluate(context.Background(), bundle, relationships)
			if err != nil {
				t.Fatalf("evaluate failed: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("expected no default findings for expected managed role, got %+v", findingTypes(findings))
			}
		})
	}
}

func TestRuleSetGroupsServiceLinkedRoleAnomalies(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	role := IAMRole{
		ARN:                      "arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
		Name:                     "AWSServiceRoleForSupport",
		Path:                     "/aws-service-role/support.amazonaws.com/",
		CreatedAt:                timePointer(now.Add(-400 * 24 * time.Hour)),
		AssumeRolePolicyDocument: trustPolicyJSON(map[string]any{"AWS": "arn:aws:iam::999999999999:root", "Service": "support.amazonaws.com"}, ""),
		PermissionPolicies: []IAMPermissionPolicy{{
			Name:           "CustomerAdmin",
			AttachmentType: "inline",
			Document:       `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}`,
		}},
	}
	bundle, relationships := normalizeRoleForRuleTest(t, role)
	findings, err := NewRuleSet(WithRuleClock(func() time.Time { return now })).Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one correlated managed-role finding, got %d: %+v", len(findings), findingTypes(findings))
	}
	finding := findings[0]
	if finding.Title != "AWS-managed role anomaly: AWSServiceRoleForSupport" || finding.Actionability != domain.FindingActionabilityReview {
		t.Fatalf("unexpected managed role finding: %+v", finding)
	}
	signals, _ := finding.Evidence["contributing_signals"].([]string)
	for _, expected := range []string{"customer_added_policy", "unexpected_external_trust", "unexpected_permission_reachability", "unexpected_trust"} {
		if !containsString(signals, expected) {
			t.Fatalf("expected signal %q in %+v", expected, signals)
		}
	}
}

func TestRuleSetEmitsInformationalConnectorTrustReview(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	roleARN := "arn:aws:iam::123456789012:role/IdentrailReadOnly"
	role := IAMRole{
		ARN:                      roleARN,
		Name:                     identrailConnectorRoleName,
		CreatedAt:                timePointer(now.Add(-400 * 24 * time.Hour)),
		AssumeRolePolicyDocument: trustPolicyJSON(map[string]any{"AWS": "arn:aws:iam::210987654321:root"}, "connector-external-id"),
		PermissionPolicies: []IAMPermissionPolicy{{
			Name:           "IdentrailReadOnlyCollector",
			AttachmentType: "inline",
			Document:       `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["iam:ListRoles","iam:GetRole"],"Resource":"*"}}`,
		}},
	}
	bundle, relationships := normalizeRoleForRuleTest(t, role)
	findings, err := NewRuleSet(
		WithRuleClock(func() time.Time { return now }),
		WithConnectorRoleExpectation(ConnectorRoleExpectation{RoleARN: roleARN, AccountID: "123456789012", TrustedAccountID: "210987654321", ExternalID: "connector-external-id"}),
	).Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one connector review, got %d: %+v", len(findings), findingTypes(findings))
	}
	finding := findings[0]
	if finding.Severity != domain.SeverityInfo || finding.Actionability != domain.FindingActionabilityObserveOnly || finding.Exploitability != domain.FindingExploitabilityNone {
		t.Fatalf("expected informational observe-only connector finding, got %+v", finding)
	}
	if finding.Evidence["external_id_condition_valid"] != true {
		t.Fatalf("expected external-id validation state without secret value, got %+v", finding.Evidence)
	}
	if encoded, err := json.Marshal(finding); err != nil || strings.Contains(string(encoded), "connector-external-id") {
		t.Fatalf("connector external ID must not be emitted, payload=%s err=%v", encoded, err)
	}
}

func TestRuleSetGroupsInvalidConnectorRoleSignals(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	role := IAMRole{
		ARN:                      "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		Name:                     identrailConnectorRoleName,
		AssumeRolePolicyDocument: trustPolicyJSON(map[string]any{"AWS": "arn:aws:iam::999999999999:root"}, "wrong-external-id"),
		PermissionPolicies: []IAMPermissionPolicy{{
			Name:           "ExpandedConnectorPolicy",
			AttachmentType: "inline",
			Document:       `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"*"}}`,
		}},
	}
	bundle, relationships := normalizeRoleForRuleTest(t, role)
	findings, err := NewRuleSet(
		WithRuleClock(func() time.Time { return now }),
		WithConnectorRoleExpectation(ConnectorRoleExpectation{
			RoleARN:          "arn:aws:iam::555555555555:role/IdentrailReadOnly",
			AccountID:        "555555555555",
			TrustedAccountID: "210987654321",
			ExternalID:       "expected-external-id",
		}),
	).Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one correlated connector drift finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Severity != domain.SeverityHigh || finding.Actionability != domain.FindingActionabilityActionRequired {
		t.Fatalf("expected actionable connector drift, got %+v", finding)
	}
	signals, _ := finding.Evidence["contributing_signals"].([]string)
	for _, expected := range []string{"connector_account_mismatch", "connector_role_mismatch", "external_id_mismatch", "permission_scope_expanded", "unexpected_trust"} {
		if !containsString(signals, expected) {
			t.Fatalf("expected signal %q in %+v", expected, signals)
		}
	}
}

func TestRuleSetDoesNotTreatAccountRootAsSubordinateIdentity(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:       identityIDFromARN("arn:aws:iam::123456789012:role/application"),
		Provider: domain.ProviderAWS,
		Type:     domain.IdentityTypeRole,
		Name:     "application",
		ARN:      "arn:aws:iam::123456789012:role/application",
	}
	findings, err := NewRuleSet(WithRuleClock(func() time.Time { return now })).Evaluate(context.Background(), providers.NormalizedBundle{Identities: []domain.Identity{identity}}, []domain.Relationship{{
		Type:       domain.RelationshipCanAssume,
		FromNodeID: "aws:principal:arn:aws:iam::123456789012:root",
		ToNodeID:   identity.ID,
	}})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if containsFindingType(findings, domain.FindingRiskyTrustPolicy) {
		t.Fatalf("same-account root is the account principal, not a subordinate identity: %+v", findings)
	}
}

func TestRuleSetAddsNormalizedFindingMetadata(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:       identityIDFromARN("arn:aws:iam::123456789012:role/ownerless"),
		Provider: domain.ProviderAWS,
		Type:     domain.IdentityTypeRole,
		Name:     "ownerless",
		ARN:      "arn:aws:iam::123456789012:role/ownerless",
	}
	findings, err := NewRuleSet(WithRuleClock(func() time.Time { return now })).Evaluate(context.Background(), providers.NormalizedBundle{Identities: []domain.Identity{identity}}, nil)
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected one normalized finding, findings=%+v err=%v", findings, err)
	}
	finding := findings[0]
	if finding.ConfidenceScore == 0 || finding.Actionability == "" || finding.Exploitability == "" || finding.EvidenceCompleteness == "" || finding.Provenance == "" {
		t.Fatalf("missing normalized top-level fields: %+v", finding)
	}
	for _, key := range []string{"account_id", "region", "source", "observed_at", "provenance", "confidence", "identity_kind", "managed_by", "actionability", "exploitability", "evidence_completeness", "evidence_boundary", "contributing_signals"} {
		if _, ok := finding.Evidence[key]; !ok {
			t.Fatalf("missing normalized evidence key %q: %+v", key, finding.Evidence)
		}
	}
}

func normalizeRoleForRuleTest(t *testing.T, role IAMRole) (providers.NormalizedBundle, []domain.Relationship) {
	t.Helper()
	payload, err := json.Marshal(role)
	if err != nil {
		t.Fatalf("marshal role: %v", err)
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), []providers.RawAsset{{Kind: "iam_role", SourceID: role.ARN, Payload: payload}})
	if err != nil {
		t.Fatalf("normalize role: %v", err)
	}
	permissions, err := NewPolicyPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions: %v", err)
	}
	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, permissions)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	return bundle, relationships
}

func trustPolicyJSON(principal map[string]any, externalID string) string {
	statement := map[string]any{
		"Effect":    "Allow",
		"Action":    "sts:AssumeRole",
		"Principal": principal,
	}
	if externalID != "" {
		statement["Condition"] = map[string]any{"StringEquals": map[string]any{"sts:ExternalId": externalID}}
	}
	document, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statement})
	return string(document)
}

func timePointer(value time.Time) *time.Time {
	return &value
}

func containsFindingType(findings []domain.Finding, findingType domain.FindingType) bool {
	for _, finding := range findings {
		if finding.Type == findingType {
			return true
		}
	}
	return false
}

func findingTypes(findings []domain.Finding) []domain.FindingType {
	types := make([]domain.FindingType, 0, len(findings))
	for _, finding := range findings {
		types = append(types, finding.Type)
	}
	return types
}
