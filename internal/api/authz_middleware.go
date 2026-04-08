package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/gin-gonic/gin"
)

const (
	policyActionFindingsRead   = "findings.read"
	policyActionFindingsTriage = "findings.triage"
	policyActionGraphRead      = "graph.read"
	policyActionScansRead      = "scans.read"
	policyActionScansRun       = "scans.run"
	policyActionRepoScansRead  = "repo_scans.read"
	policyActionRepoScansRun   = "repo_scans.run"
)

type routePolicy struct {
	Action          string
	ResourceType    string
	ResourceIDParam string
}

type routePolicyRegistry map[string]routePolicy

func newRoutePolicyRegistry() routePolicyRegistry {
	return routePolicyRegistry{
		routePolicyKey(http.MethodGet, "/v1/findings"): {
			Action:       policyActionFindingsRead,
			ResourceType: "finding",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/:finding_id"): {
			Action:          policyActionFindingsRead,
			ResourceType:    "finding",
			ResourceIDParam: "finding_id",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/:finding_id/history"): {
			Action:          policyActionFindingsRead,
			ResourceType:    "finding_history",
			ResourceIDParam: "finding_id",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/:finding_id/exports"): {
			Action:          policyActionFindingsRead,
			ResourceType:    "finding_export",
			ResourceIDParam: "finding_id",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/trends"): {
			Action:       policyActionFindingsRead,
			ResourceType: "finding_trend",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/summary"): {
			Action:       policyActionFindingsRead,
			ResourceType: "finding_summary",
		},
		routePolicyKey(http.MethodPatch, "/v1/findings/:finding_id/triage"): {
			Action:          policyActionFindingsTriage,
			ResourceType:    "finding",
			ResourceIDParam: "finding_id",
		},
		routePolicyKey(http.MethodGet, "/v1/identities"): {
			Action:       policyActionGraphRead,
			ResourceType: "identity",
		},
		routePolicyKey(http.MethodGet, "/v1/relationships"): {
			Action:       policyActionGraphRead,
			ResourceType: "relationship",
		},
		routePolicyKey(http.MethodGet, "/v1/ownership/signals"): {
			Action:       policyActionGraphRead,
			ResourceType: "ownership_signal",
		},
		routePolicyKey(http.MethodGet, "/v1/scans"): {
			Action:       policyActionScansRead,
			ResourceType: "scan",
		},
		routePolicyKey(http.MethodGet, "/v1/scans/:scan_id/diff"): {
			Action:          policyActionScansRead,
			ResourceType:    "scan_diff",
			ResourceIDParam: "scan_id",
		},
		routePolicyKey(http.MethodGet, "/v1/scans/:scan_id/events"): {
			Action:          policyActionScansRead,
			ResourceType:    "scan_event",
			ResourceIDParam: "scan_id",
		},
		routePolicyKey(http.MethodPost, "/v1/scans"): {
			Action:       policyActionScansRun,
			ResourceType: "scan",
		},
		routePolicyKey(http.MethodGet, "/v1/repo-scans"): {
			Action:       policyActionRepoScansRead,
			ResourceType: "repo_scan",
		},
		routePolicyKey(http.MethodGet, "/v1/repo-scans/:repo_scan_id"): {
			Action:          policyActionRepoScansRead,
			ResourceType:    "repo_scan",
			ResourceIDParam: "repo_scan_id",
		},
		routePolicyKey(http.MethodGet, "/v1/repo-findings"): {
			Action:       policyActionRepoScansRead,
			ResourceType: "repo_finding",
		},
		routePolicyKey(http.MethodPost, "/v1/repo-scans"): {
			Action:       policyActionRepoScansRun,
			ResourceType: "repo_scan",
		},
	}
}

func (r routePolicyRegistry) lookup(method string, fullPath string) (routePolicy, bool) {
	policy, exists := r[routePolicyKey(method, fullPath)]
	return policy, exists
}

func routePolicyKey(method string, fullPath string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + strings.TrimSpace(fullPath)
}

func defaultRouteActionRoleGrants() map[string][]string {
	readRoles := []string{scopeRead, scopeWrite, scopeAdmin}
	writeRoles := []string{scopeWrite, scopeAdmin}
	return map[string][]string{
		policyActionFindingsRead:   readRoles,
		policyActionFindingsTriage: writeRoles,
		policyActionGraphRead:      readRoles,
		policyActionScansRead:      readRoles,
		policyActionScansRun:       writeRoles,
		policyActionRepoScansRead:  readRoles,
		policyActionRepoScansRun:   writeRoles,
	}
}

func newCentralPolicyEngine() *PolicyEngine {
	return NewPolicyEngine(
		newTenantIsolationEvaluator(),
		newRBACPolicyEvaluator(defaultRouteActionRoleGrants()),
		nil,
		nil,
	)
}

func requireCentralPolicyMiddleware(engine *PolicyEngine, registry routePolicyRegistry, writeKeys []string, scopedKeys map[string][]string) gin.HandlerFunc {
	normalizedWriteKeys := normalizeKeyList(writeKeys)
	return func(c *gin.Context) {
		fullPath := strings.TrimSpace(c.FullPath())
		if fullPath == "" {
			c.Next()
			return
		}
		policy, exists := registry.lookup(c.Request.Method, fullPath)
		if !exists {
			c.Next()
			return
		}

		if !hasAuthContext(c) {
			// Keep local/dev behavior unchanged when authentication is disabled.
			c.Next()
			return
		}

		decision, err := engine.Decide(c.Request.Context(), buildPolicyInputFromGinContext(c, policy, normalizedWriteKeys, scopedKeys))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			return
		}
		if !decision.Allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		c.Set("authz.stage", string(decision.Stage))
		c.Next()
	}
}

func buildPolicyInputFromGinContext(c *gin.Context, policy routePolicy, writeKeys []string, scopedKeys map[string][]string) PolicyInput {
	scope := db.ScopeFromContext(c.Request.Context())
	resourceID := ""
	if strings.TrimSpace(policy.ResourceIDParam) != "" {
		resourceID = strings.TrimSpace(c.Param(policy.ResourceIDParam))
	}
	return PolicyInput{
		Subject: PolicySubject{
			Type:        authContextString(c, "auth.principal_type"),
			ID:          authContextString(c, "auth.principal_id"),
			TenantID:    firstNonEmpty(authContextString(c, "auth.tenant_id"), strings.TrimSpace(scope.TenantID)),
			WorkspaceID: firstNonEmpty(authContextString(c, "auth.workspace_id"), strings.TrimSpace(scope.WorkspaceID)),
			Roles:       policyRolesFromAuth(c, writeKeys, scopedKeys),
		},
		Action: strings.ToLower(strings.TrimSpace(policy.Action)),
		Resource: PolicyResource{
			Type:        strings.TrimSpace(policy.ResourceType),
			ID:          resourceID,
			TenantID:    strings.TrimSpace(scope.TenantID),
			WorkspaceID: strings.TrimSpace(scope.WorkspaceID),
		},
		Context: PolicyContext{
			RequestPath:   strings.TrimSpace(c.FullPath()),
			RequestMethod: strings.ToUpper(strings.TrimSpace(c.Request.Method)),
			Attributes: map[string]string{
				policyContextTenantIDKey:    strings.TrimSpace(scope.TenantID),
				policyContextWorkspaceIDKey: strings.TrimSpace(scope.WorkspaceID),
			},
		},
	}
}

func firstNonEmpty(primary string, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	return strings.TrimSpace(fallback)
}

func hasAuthContext(c *gin.Context) bool {
	if c == nil {
		return false
	}
	if _, exists := c.Get("auth.scope_set"); exists {
		return true
	}
	if authContextString(c, "auth.api_key") != "" {
		return true
	}
	if authContextString(c, "auth.subject") != "" {
		return true
	}
	return false
}

func normalizeKeyList(keys []string) []string {
	normalized := make([]string, 0, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func policyRolesFromAuth(c *gin.Context, writeKeys []string, scopedKeys map[string][]string) []string {
	if c == nil {
		return nil
	}
	if scopeSetValue, exists := c.Get("auth.scope_set"); exists {
		scopes, ok := scopeSetValue.(scopeSet)
		if !ok {
			return nil
		}
		roles := map[string]struct{}{}
		if scopes.has(scopeAdmin) {
			roles[scopeAdmin] = struct{}{}
		}
		if scopes.has(scopeWrite) {
			roles[scopeWrite] = struct{}{}
		}
		if scopes.has(scopeRead) {
			roles[scopeRead] = struct{}{}
		}
		result := make([]string, 0, len(roles))
		for role := range roles {
			result = append(result, role)
		}
		sort.Strings(result)
		return result
	}

	legacyKey := authContextString(c, "auth.api_key")
	if legacyKey == "" {
		return nil
	}
	// In scoped-key mode, the auth middleware should always set scope_set for valid keys.
	if len(scopedKeys) > 0 {
		return nil
	}
	roles := []string{scopeRead}
	if keyInList(writeKeys, legacyKey) {
		roles = append(roles, scopeWrite)
	}
	return roles
}
