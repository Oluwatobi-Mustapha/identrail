package db

import (
	"context"
	"crypto/sha256"
	"strings"
	"time"
)

func (m *MemoryStore) CreateAWSConnectorOnboardingAttempt(ctx context.Context, attempt AWSConnectorOnboardingAttempt) (AWSConnectorOnboardingAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized, err := normalizeAWSConnectorOnboardingAttempt(ctx, attempt)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	if _, exists := m.awsOnboardingAttempts[normalized.AttemptID]; exists {
		return AWSConnectorOnboardingAttempt{}, ErrConflict
	}
	connectorKey := tenancyConnectorKey(normalized.TenantID, normalized.WorkspaceID, normalized.ProjectID, normalized.ConnectorID)
	if _, exists := m.connectors[connectorKey]; !exists {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	for _, existing := range m.awsOnboardingAttempts {
		if existing.TenantID == normalized.TenantID &&
			existing.WorkspaceID == normalized.WorkspaceID &&
			existing.ProjectID == normalized.ProjectID &&
			existing.ConnectorID == normalized.ConnectorID &&
			awsOnboardingAttemptActive(existing.Status) {
			return AWSConnectorOnboardingAttempt{}, ErrConflict
		}
	}
	m.awsOnboardingAttempts[normalized.AttemptID] = cloneAWSConnectorOnboardingAttempt(normalized)
	return cloneAWSConnectorOnboardingAttempt(normalized), nil
}

func (m *MemoryStore) GetAWSConnectorOnboardingAttempt(ctx context.Context, workspaceID string, projectID string, attemptID string) (AWSConnectorOnboardingAttempt, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	attempt, ok := m.awsOnboardingAttempts[strings.TrimSpace(attemptID)]
	if !ok || attempt.TenantID != scope.TenantID || attempt.WorkspaceID != resolvedWorkspaceID || attempt.ProjectID != strings.TrimSpace(projectID) {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	return cloneAWSConnectorOnboardingAttempt(attempt), nil
}

func (m *MemoryStore) GetAWSConnectorOnboardingAttemptAnyScope(_ context.Context, attemptID string) (AWSConnectorOnboardingAttempt, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	attempt, ok := m.awsOnboardingAttempts[strings.TrimSpace(attemptID)]
	if !ok {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	return cloneAWSConnectorOnboardingAttempt(attempt), nil
}

func (m *MemoryStore) GetActiveAWSConnectorOnboardingAttempt(ctx context.Context, workspaceID string, projectID string, connectorID string) (AWSConnectorOnboardingAttempt, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	var newest AWSConnectorOnboardingAttempt
	for _, attempt := range m.awsOnboardingAttempts {
		if attempt.TenantID != scope.TenantID || attempt.WorkspaceID != resolvedWorkspaceID || attempt.ProjectID != strings.TrimSpace(projectID) || attempt.ConnectorID != strings.TrimSpace(connectorID) || !awsOnboardingAttemptActive(attempt.Status) {
			continue
		}
		if newest.AttemptID == "" || attempt.CreatedAt.After(newest.CreatedAt) {
			newest = attempt
		}
	}
	if newest.AttemptID == "" {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	return cloneAWSConnectorOnboardingAttempt(newest), nil
}

// GetLatestAWSConnectorOnboardingAttempt returns the newest attempt regardless
// of lifecycle status. Resume flows use it to issue an authenticated
// CloudFormation Update against an already-bound stack instead of creating a
// second attempt that cannot claim the existing stack.
func (m *MemoryStore) GetLatestAWSConnectorOnboardingAttempt(ctx context.Context, workspaceID string, projectID string, connectorID string) (AWSConnectorOnboardingAttempt, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	var newest AWSConnectorOnboardingAttempt
	for _, attempt := range m.awsOnboardingAttempts {
		if attempt.TenantID != scope.TenantID || attempt.WorkspaceID != resolvedWorkspaceID || attempt.ProjectID != strings.TrimSpace(projectID) || attempt.ConnectorID != strings.TrimSpace(connectorID) {
			continue
		}
		if newest.AttemptID == "" || attempt.CreatedAt.After(newest.CreatedAt) || (attempt.CreatedAt.Equal(newest.CreatedAt) && attempt.UpdatedAt.After(newest.UpdatedAt)) {
			newest = attempt
		}
	}
	if newest.AttemptID == "" {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	return cloneAWSConnectorOnboardingAttempt(newest), nil
}

// GetLatestResumableAWSConnectorOnboardingAttempt returns the newest attempt
// that can safely resume an already-created CloudFormation stack. Unbound
// attempts are intentionally ignored so a newer draft cannot hide the older
// attempt that owns the durable stack identity.
func (m *MemoryStore) GetLatestResumableAWSConnectorOnboardingAttempt(ctx context.Context, workspaceID string, projectID string, connectorID string, providerTopicARN string, region string) (AWSConnectorOnboardingAttempt, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	providerTopicARN = strings.TrimSpace(providerTopicARN)
	region = strings.ToLower(strings.TrimSpace(region))
	var newest AWSConnectorOnboardingAttempt
	for _, attempt := range m.awsOnboardingAttempts {
		if attempt.TenantID != scope.TenantID ||
			attempt.WorkspaceID != resolvedWorkspaceID ||
			attempt.ProjectID != strings.TrimSpace(projectID) ||
			attempt.ConnectorID != strings.TrimSpace(connectorID) ||
			attempt.ProviderTopicARN != providerTopicARN ||
			attempt.DeploymentRegion != region ||
			!awsOnboardingAttemptHasBoundStack(attempt) {
			continue
		}
		if newest.AttemptID == "" || attempt.CreatedAt.After(newest.CreatedAt) || (attempt.CreatedAt.Equal(newest.CreatedAt) && attempt.UpdatedAt.After(newest.UpdatedAt)) {
			newest = attempt
		}
	}
	if newest.AttemptID == "" {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	return cloneAWSConnectorOnboardingAttempt(newest), nil
}

func (m *MemoryStore) UpdateAWSConnectorOnboardingAttempt(ctx context.Context, attempt AWSConnectorOnboardingAttempt, expectedVersion int64) (AWSConnectorOnboardingAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalized, err := normalizeAWSConnectorOnboardingAttempt(ctx, attempt)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	existing, ok := m.awsOnboardingAttempts[normalized.AttemptID]
	if !ok {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	// Postgres binds an attempt to its (tenant, workspace, project, connector)
	// tuple via a foreign key. Enforce the same invariant here so a caller
	// cannot silently move an attempt to another connector or project.
	if existing.TenantID != normalized.TenantID ||
		existing.WorkspaceID != normalized.WorkspaceID ||
		existing.ProjectID != normalized.ProjectID ||
		existing.ConnectorID != normalized.ConnectorID {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	if existing.Version != expectedVersion {
		return AWSConnectorOnboardingAttempt{}, ErrConflict
	}
	if awsOnboardingAttemptActive(normalized.Status) {
		for attemptID, other := range m.awsOnboardingAttempts {
			if attemptID != normalized.AttemptID &&
				other.TenantID == normalized.TenantID &&
				other.WorkspaceID == normalized.WorkspaceID &&
				other.ProjectID == normalized.ProjectID &&
				other.ConnectorID == normalized.ConnectorID &&
				awsOnboardingAttemptActive(other.Status) {
				return AWSConnectorOnboardingAttempt{}, ErrConflict
			}
		}
	}
	normalized.CreatedAt = existing.CreatedAt
	normalized.Version = existing.Version + 1
	m.awsOnboardingAttempts[normalized.AttemptID] = cloneAWSConnectorOnboardingAttempt(normalized)
	return cloneAWSConnectorOnboardingAttempt(normalized), nil
}

func normalizeAWSConnectorOnboardingAttempt(ctx context.Context, attempt AWSConnectorOnboardingAttempt) (AWSConnectorOnboardingAttempt, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	attempt.TenantID = scope.TenantID
	workspaceID, err := ResolveScopedWorkspaceID(scope, attempt.WorkspaceID)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	attempt.WorkspaceID = workspaceID
	attempt.AttemptID = strings.TrimSpace(attempt.AttemptID)
	attempt.ProjectID = strings.TrimSpace(attempt.ProjectID)
	attempt.ConnectorID = strings.TrimSpace(attempt.ConnectorID)
	attempt.Status = strings.TrimSpace(attempt.Status)
	attempt.TokenKeyVersion = strings.TrimSpace(attempt.TokenKeyVersion)
	attempt.ProviderTopicARN = strings.TrimSpace(attempt.ProviderTopicARN)
	attempt.TemplateVersion = strings.TrimSpace(attempt.TemplateVersion)
	attempt.TemplateChecksum = strings.TrimSpace(attempt.TemplateChecksum)
	attempt.DeploymentRegion = strings.TrimSpace(attempt.DeploymentRegion)
	if attempt.AttemptID == "" || attempt.ProjectID == "" || attempt.ConnectorID == "" ||
		!awsOnboardingAttemptStatusValid(attempt.Status) || len(attempt.TokenHash) != sha256.Size ||
		attempt.TokenKeyVersion == "" || attempt.ProviderTopicARN == "" || attempt.TemplateVersion == "" ||
		attempt.TemplateChecksum == "" || attempt.DeploymentRegion == "" || attempt.ExpiresAt.IsZero() {
		return AWSConnectorOnboardingAttempt{}, ErrInvalidAWSConnectorOnboardingAttempt
	}
	now := time.Now().UTC()
	if attempt.CreatedAt.IsZero() {
		attempt.CreatedAt = now
	}
	if attempt.UpdatedAt.IsZero() {
		attempt.UpdatedAt = attempt.CreatedAt
	}
	if attempt.Version <= 0 {
		attempt.Version = 1
	}
	return attempt, nil
}

func awsOnboardingAttemptStatusValid(status string) bool {
	switch status {
	case AWSConnectorOnboardingAttemptWaiting,
		AWSConnectorOnboardingAttemptRegistering,
		AWSConnectorOnboardingAttemptValidating,
		AWSConnectorOnboardingAttemptConnected,
		AWSConnectorOnboardingAttemptNeedsFix,
		AWSConnectorOnboardingAttemptExpired,
		AWSConnectorOnboardingAttemptFailed:
		return true
	default:
		return false
	}
}

func awsOnboardingAttemptActive(status string) bool {
	switch status {
	case AWSConnectorOnboardingAttemptWaiting, AWSConnectorOnboardingAttemptRegistering, AWSConnectorOnboardingAttemptValidating:
		return true
	default:
		return false
	}
}

func awsOnboardingAttemptHasBoundStack(attempt AWSConnectorOnboardingAttempt) bool {
	if attempt.Status != AWSConnectorOnboardingAttemptConnected && attempt.Status != AWSConnectorOnboardingAttemptNeedsFix {
		return false
	}
	return strings.TrimSpace(attempt.StackID) != "" &&
		strings.TrimSpace(attempt.BootstrapRequestID) != "" &&
		strings.TrimSpace(attempt.RegisterRequestID) != ""
}

func cloneAWSConnectorOnboardingAttempt(attempt AWSConnectorOnboardingAttempt) AWSConnectorOnboardingAttempt {
	attempt.TokenHash = append([]byte(nil), attempt.TokenHash...)
	return attempt
}
