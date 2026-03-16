package domain

import "strings"

// Validate ensures the identity has enough information for deduplication and graph linking.
func (i Identity) Validate() bool {
	return i.ID != "" && i.Provider != "" && i.Type != "" && strings.TrimSpace(i.Name) != ""
}

// Validate ensures relationships remain queryable and directionally consistent.
func (r Relationship) Validate() bool {
	return r.ID != "" && r.Type != "" && r.FromNodeID != "" && r.ToNodeID != ""
}

// Validate ensures findings are actionable and correctly categorized.
func (f Finding) Validate() bool {
	return f.ID != "" && f.Type != "" && f.Severity != "" && strings.TrimSpace(f.Title) != ""
}
