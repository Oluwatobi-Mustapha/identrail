package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
)

func TestCompileRouteAuthorizationPolicyBundleRejectsInvalidABACPredicate(t *testing.T) {
	bundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "PATCH",
			Path:         "/v1/findings/:finding_id/triage",
			Action:       policyActionFindingsTriage,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsTriage: {scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsTriage: {
				AnyOf: []abacClause{{
					AllOf: []abacPredicate{{
						Source:        abacAttributeSourceSubject,
						Key:           policyAttributeOwnerTeam,
						Operator:      abacOperatorEqualsAttribute,
						CompareSource: abacAttributeSourceResource,
					}},
				}},
			},
		},
	}

	_, err := compileRouteAuthorizationPolicyBundle(bundle)
	if err == nil {
		t.Fatal("expected invalid abac expression to fail compilation")
	}
	if !strings.Contains(err.Error(), "compare_key") {
		t.Fatalf("expected compare_key error, got %v", err)
	}
}

func TestCompileRouteAuthorizationPolicyBundleRejectsInvalidReBACRelation(t *testing.T) {
	bundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "PATCH",
			Path:         "/v1/findings/:finding_id/triage",
			Action:       policyActionFindingsTriage,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsTriage: {scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsTriage: {
				AnyOf: []abacClause{{}},
			},
		},
		ReBACPolicies: map[string]rebacActionPolicy{
			policyActionFindingsTriage: {
				AnyOf: []rebacRelationPath{{Relations: []string{"viewer"}}},
			},
		},
	}

	_, err := compileRouteAuthorizationPolicyBundle(bundle)
	if err == nil {
		t.Fatal("expected invalid rebac relation to fail compilation")
	}
	if !strings.Contains(err.Error(), "unsupported relation") {
		t.Fatalf("expected unsupported relation error, got %v", err)
	}
}

func TestCentralPolicyRuntimeResolverFallsBackWhenNoActiveRollout(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()
	resolver := newCentralPolicyRuntimeResolverWithPolicySet(store, defaultCentralPolicySetID)

	runtimePolicy, err := resolver.Resolve(ctx)
	if err != nil {
		t.Fatalf("resolve runtime policy fallback: %v", err)
	}
	if runtimePolicy.Source != "built_in_default" {
		t.Fatalf("expected built-in fallback source, got %q", runtimePolicy.Source)
	}
	if _, exists := runtimePolicy.Registry.lookup("POST", "/v1/scans"); !exists {
		t.Fatal("expected built-in route policy for POST /v1/scans")
	}
}

func TestCentralPolicyRuntimeResolverUsesPersistedActiveVersion(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()
	resolver := newCentralPolicyRuntimeResolverWithPolicySet(store, defaultCentralPolicySetID)

	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	bundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "GET",
			Path:         "/v1/findings",
			Action:       policyActionFindingsRead,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsRead: {scopeRead, scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsRead: {
				AnyOf: []abacClause{{}},
			},
		},
	}
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal policy bundle: %v", err)
	}

	createdVersion, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		Bundle:      string(bundleBytes),
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	if err := store.UpsertAuthzPolicyRollout(ctx, db.AuthzPolicyRollout{
		PolicySetID:   defaultCentralPolicySetID,
		ActiveVersion: &createdVersion.Version,
		Mode:          db.AuthzPolicyRolloutModeEnforce,
		UpdatedBy:     "test",
	}); err != nil {
		t.Fatalf("upsert policy rollout: %v", err)
	}

	runtimePolicy, err := resolver.Resolve(ctx)
	if err != nil {
		t.Fatalf("resolve runtime policy persisted active version: %v", err)
	}
	if runtimePolicy.Source != "persisted_active_version" {
		t.Fatalf("expected persisted source, got %q", runtimePolicy.Source)
	}
	if runtimePolicy.Version != 1 {
		t.Fatalf("expected active version 1, got %d", runtimePolicy.Version)
	}
	policy, exists := runtimePolicy.Registry.lookup("GET", "/v1/findings")
	if !exists {
		t.Fatal("expected persisted route policy for GET /v1/findings")
	}
	if policy.Action != policyActionFindingsRead {
		t.Fatalf("expected persisted action %q, got %q", policyActionFindingsRead, policy.Action)
	}
}

func TestCentralPolicyRuntimeResolverFallsBackWhenRolloutIsShadow(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()
	resolver := newCentralPolicyRuntimeResolverWithPolicySet(store, defaultCentralPolicySetID)

	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	bundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "GET",
			Path:         "/v1/findings",
			Action:       policyActionFindingsRead,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsRead: {scopeRead, scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsRead: {
				AnyOf: []abacClause{{}},
			},
		},
	}
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal policy bundle: %v", err)
	}
	createdVersion, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		Bundle:      string(bundleBytes),
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatalf("create policy version: %v", err)
	}
	if err := store.UpsertAuthzPolicyRollout(ctx, db.AuthzPolicyRollout{
		PolicySetID:   defaultCentralPolicySetID,
		ActiveVersion: &createdVersion.Version,
		Mode:          db.AuthzPolicyRolloutModeShadow,
		UpdatedBy:     "test",
	}); err != nil {
		t.Fatalf("upsert policy rollout: %v", err)
	}

	runtimePolicy, err := resolver.Resolve(ctx)
	if err != nil {
		t.Fatalf("resolve runtime policy for shadow mode: %v", err)
	}
	if runtimePolicy.Source != "built_in_default" {
		t.Fatalf("expected built-in fallback source for shadow mode, got %q", runtimePolicy.Source)
	}
	if runtimePolicy.RolloutMode != db.AuthzPolicyRolloutModeShadow {
		t.Fatalf("expected shadow rollout mode, got %q", runtimePolicy.RolloutMode)
	}
	if runtimePolicy.Version != 0 {
		t.Fatalf("expected no enforced version in shadow fallback, got %d", runtimePolicy.Version)
	}
}

func TestValidateAuthzPolicyRolloutActivationRejectsInvalidBundle(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := testAuthzPolicyScopeContext()

	if err := store.UpsertAuthzPolicySet(ctx, db.AuthzPolicySet{
		PolicySetID: defaultCentralPolicySetID,
		DisplayName: "Central Authorization",
		CreatedBy:   "test",
	}); err != nil {
		t.Fatalf("upsert policy set: %v", err)
	}

	invalidBundle := routeAuthorizationPolicyBundle{
		SchemaVersion: routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies: []routePolicyDefinition{{
			Method:       "PATCH",
			Path:         "/v1/findings/:finding_id/triage",
			Action:       policyActionFindingsTriage,
			ResourceType: "finding",
		}},
		RBACActionRole: map[string][]string{
			policyActionFindingsTriage: {scopeWrite, scopeAdmin},
		},
		ABACPolicies: map[string]abacActionPolicy{
			policyActionFindingsTriage: {
				AnyOf: []abacClause{{
					AllOf: []abacPredicate{{
						Source:   abacAttributeSourceSubject,
						Key:      policyAttributeOwnerTeam,
						Operator: abacOperatorOneOf,
					}},
				}},
			},
		},
	}
	bundleBytes, err := json.Marshal(invalidBundle)
	if err != nil {
		t.Fatalf("marshal invalid bundle: %v", err)
	}
	version, err := store.CreateAuthzPolicyVersion(ctx, db.AuthzPolicyVersion{
		PolicySetID: defaultCentralPolicySetID,
		Version:     1,
		Bundle:      string(bundleBytes),
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatalf("create invalid policy version: %v", err)
	}
	rollout := db.AuthzPolicyRollout{
		PolicySetID:   defaultCentralPolicySetID,
		ActiveVersion: &version.Version,
		Mode:          db.AuthzPolicyRolloutModeEnforce,
	}
	if err := validateAuthzPolicyRolloutActivation(ctx, store, defaultCentralPolicySetID, rollout); err == nil {
		t.Fatal("expected invalid bundle to fail activation validation")
	}
}

func testAuthzPolicyScopeContext() context.Context {
	return db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
}
