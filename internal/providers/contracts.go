package providers

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

var supportedPolicyTypes = map[string]struct{}{
	"permission": {},
	"trust":      {},
}

// SourceError captures non-fatal collection issues discovered during one run.
// These errors are surfaced as scan lifecycle warnings without failing the scan.
type SourceError struct {
	Collector string `json:"collector"`
	SourceID  string `json:"source_id,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// DiagnosticCollector is an optional collector contract for partial-failure reporting.
type DiagnosticCollector interface {
	CollectWithDiagnostics(ctx context.Context) ([]RawAsset, []SourceError, error)
}

// ValidateNormalizedBundle enforces required normalized-schema invariants for v1.
func ValidateNormalizedBundle(bundle NormalizedBundle) error {
	identityIDs := make(map[string]struct{}, len(bundle.Identities))
	for i, identity := range bundle.Identities {
		if !identity.Validate() {
			return fmt.Errorf("invalid identity at index %d", i)
		}
		if _, exists := identityIDs[identity.ID]; exists {
			return fmt.Errorf("duplicate identity id %q", identity.ID)
		}
		identityIDs[identity.ID] = struct{}{}
	}

	workloadIDs := make(map[string]struct{}, len(bundle.Workloads))
	for i, workload := range bundle.Workloads {
		if strings.TrimSpace(workload.ID) == "" ||
			strings.TrimSpace(string(workload.Provider)) == "" ||
			strings.TrimSpace(workload.Type) == "" ||
			strings.TrimSpace(workload.Name) == "" {
			return fmt.Errorf("invalid workload at index %d", i)
		}
		if _, exists := workloadIDs[workload.ID]; exists {
			return fmt.Errorf("duplicate workload id %q", workload.ID)
		}
		workloadIDs[workload.ID] = struct{}{}
	}

	policyIDs := make(map[string]struct{}, len(bundle.Policies))
	for i, policy := range bundle.Policies {
		if strings.TrimSpace(policy.ID) == "" ||
			strings.TrimSpace(string(policy.Provider)) == "" ||
			strings.TrimSpace(policy.Name) == "" ||
			strings.TrimSpace(policy.RawRef) == "" {
			return fmt.Errorf("invalid policy at index %d", i)
		}
		if _, exists := policyIDs[policy.ID]; exists {
			return fmt.Errorf("duplicate policy id %q", policy.ID)
		}
		policyIDs[policy.ID] = struct{}{}
		if err := validatePolicyNormalized(policy.Normalized, identityIDs); err != nil {
			return fmt.Errorf("invalid policy %q normalized payload: %w", policy.ID, err)
		}
	}

	return nil
}

func validatePolicyNormalized(normalized map[string]any, identityIDs map[string]struct{}) error {
	if len(normalized) == 0 {
		return fmt.Errorf("missing normalized payload")
	}
	policyType, _ := normalized["policy_type"].(string)
	policyType = strings.ToLower(strings.TrimSpace(policyType))
	if _, ok := supportedPolicyTypes[policyType]; !ok {
		return fmt.Errorf("unsupported policy_type %q", policyType)
	}
	identityID, _ := normalized["identity_id"].(string)
	identityID = strings.TrimSpace(identityID)
	if identityID == "" {
		return fmt.Errorf("missing identity_id")
	}
	if _, exists := identityIDs[identityID]; !exists {
		return fmt.Errorf("unknown identity_id %q", identityID)
	}

	switch policyType {
	case "permission":
		statements, ok := normalized["statements"].([]map[string]any)
		if !ok || len(statements) == 0 {
			// JSON roundtrip often decodes to []any; support that shape too.
			rawStatements, rawOK := normalized["statements"].([]any)
			if !rawOK || len(rawStatements) == 0 {
				return fmt.Errorf("missing permission statements")
			}
			for _, raw := range rawStatements {
				statement, ok := raw.(map[string]any)
				if !ok {
					return fmt.Errorf("invalid statement type %T", raw)
				}
				if err := validateStatement(statement); err != nil {
					return err
				}
			}
			return nil
		}
		for _, statement := range statements {
			if err := validateStatement(statement); err != nil {
				return err
			}
		}
	case "trust":
		principals := extractStringSlice(normalized["principals"])
		if len(principals) == 0 {
			return fmt.Errorf("missing trust principals")
		}
	}
	return nil
}

func validateStatement(statement map[string]any) error {
	effect, _ := statement["effect"].(string)
	if strings.TrimSpace(effect) == "" {
		return fmt.Errorf("statement missing effect")
	}
	actions := extractStringSlice(statement["actions"])
	if len(actions) == 0 {
		return fmt.Errorf("statement missing actions")
	}
	resources := extractStringSlice(statement["resources"])
	if len(resources) == 0 {
		return fmt.Errorf("statement missing resources")
	}
	return nil
}

func extractStringSlice(raw any) []string {
	switch values := raw.(type) {
	case []string:
		copied := append([]string(nil), values...)
		slices.Sort(copied)
		return slices.Compact(copied)
	case []any:
		result := make([]string, 0, len(values))
		seen := map[string]struct{}{}
		for _, value := range values {
			text, _ := value.(string)
			normalized := strings.TrimSpace(text)
			if normalized == "" {
				continue
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
		slices.Sort(result)
		return result
	default:
		return nil
	}
}
