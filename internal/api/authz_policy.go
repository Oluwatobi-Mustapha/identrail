package api

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// PolicyStage identifies one authorization layer in the centralized decision pipeline.
type PolicyStage string

const (
	PolicyStageTenantIsolation PolicyStage = "tenant_isolation"
	PolicyStageRBAC            PolicyStage = "rbac"
	PolicyStageABAC            PolicyStage = "abac"
	PolicyStageReBAC           PolicyStage = "rebac"
	PolicyStageDefaultDeny     PolicyStage = "default_deny"
)

// PolicyOutcome captures one evaluator result.
type PolicyOutcome string

const (
	PolicyOutcomeNoOpinion PolicyOutcome = "no_op"
	PolicyOutcomeAllow     PolicyOutcome = "allow"
	PolicyOutcomeDeny      PolicyOutcome = "deny"
	PolicyOutcomeSkipped   PolicyOutcome = "skipped"
)

// PolicySubject is the actor for one authorization decision.
type PolicySubject struct {
	Type        string
	ID          string
	TenantID    string
	WorkspaceID string
	Groups      []string
	Roles       []string
	Attributes  map[string]string
}

// PolicyResource identifies the target object.
type PolicyResource struct {
	Type        string
	ID          string
	TenantID    string
	WorkspaceID string
	Attributes  map[string]string
}

// PolicyContext captures request-time facts used in policy evaluation.
type PolicyContext struct {
	RequestPath   string
	RequestMethod string
	Now           time.Time
	Attributes    map[string]string
}

// PolicyInput is the single input model for centralized authorization.
type PolicyInput struct {
	Subject  PolicySubject
	Action   string
	Resource PolicyResource
	Context  PolicyContext
}

// PolicyDecision is the normalized authorization outcome.
type PolicyDecision struct {
	Allowed bool
	Stage   PolicyStage
	Reason  string
}

// PolicyTraceStep captures one stage-level evaluator outcome for explainability.
type PolicyTraceStep struct {
	Stage   PolicyStage   `json:"stage"`
	Outcome PolicyOutcome `json:"outcome"`
	Reason  string        `json:"reason"`
}

// PolicyEvaluator evaluates one authorization layer.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, input PolicyInput) (PolicyOutcome, string, error)
}

// PolicyEngine evaluates authorization in strict order:
// tenant isolation -> RBAC -> ABAC -> ReBAC -> default deny.
type PolicyEngine struct {
	TenantIsolationEvaluator PolicyEvaluator
	RBACEvaluator            PolicyEvaluator
	ABACEvaluator            PolicyEvaluator
	ReBACEvaluator           PolicyEvaluator
}

// NewPolicyEngine creates one centralized authorization engine.
func NewPolicyEngine(tenantIsolation PolicyEvaluator, rbac PolicyEvaluator, abac PolicyEvaluator, rebac PolicyEvaluator) *PolicyEngine {
	return &PolicyEngine{
		TenantIsolationEvaluator: tenantIsolation,
		RBACEvaluator:            rbac,
		ABACEvaluator:            abac,
		ReBACEvaluator:           rebac,
	}
}

// Decide evaluates authorization policies and returns one normalized decision.
func (p *PolicyEngine) Decide(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	decision, _, err := p.DecideWithTrace(ctx, input)
	return decision, err
}

// DecideWithTrace evaluates authorization and returns a full stage-by-stage trace.
func (p *PolicyEngine) DecideWithTrace(ctx context.Context, input PolicyInput) (PolicyDecision, []PolicyTraceStep, error) {
	stages := []struct {
		name      PolicyStage
		evaluator PolicyEvaluator
	}{
		{name: PolicyStageTenantIsolation, evaluator: nil},
		{name: PolicyStageRBAC, evaluator: nil},
		{name: PolicyStageABAC, evaluator: nil},
		{name: PolicyStageReBAC, evaluator: nil},
	}

	if p == nil {
		trace := make([]PolicyTraceStep, 0, len(stages)+1)
		for _, stage := range stages {
			trace = append(trace, PolicyTraceStep{
				Stage:   stage.name,
				Outcome: PolicyOutcomeSkipped,
				Reason:  "policy engine is not configured",
			})
		}
		decision := denyDecision(PolicyStageDefaultDeny, "authorization policy engine is not configured")
		trace = append(trace, PolicyTraceStep{
			Stage:   PolicyStageDefaultDeny,
			Outcome: PolicyOutcomeDeny,
			Reason:  decision.Reason,
		})
		return decision, trace, nil
	}

	stages[0].evaluator = p.TenantIsolationEvaluator
	stages[1].evaluator = p.RBACEvaluator
	stages[2].evaluator = p.ABACEvaluator
	stages[3].evaluator = p.ReBACEvaluator

	trace := make([]PolicyTraceStep, 0, len(stages)+1)
	for index, stage := range stages {
		if stage.evaluator == nil {
			trace = append(trace, PolicyTraceStep{
				Stage:   stage.name,
				Outcome: PolicyOutcomeNoOpinion,
				Reason:  "stage evaluator is not configured",
			})
			continue
		}
		outcome, reason, err := stage.evaluator.Evaluate(ctx, input)
		if err != nil {
			return PolicyDecision{}, trace, fmt.Errorf("evaluate %s policy: %w", stage.name, err)
		}
		reason = strings.TrimSpace(reason)
		if reason == "" {
			switch outcome {
			case PolicyOutcomeNoOpinion:
				reason = "no policy opinion"
			case PolicyOutcomeAllow:
				reason = "policy grants action"
			case PolicyOutcomeDeny:
				reason = "policy denies action"
			}
		}
		trace = append(trace, PolicyTraceStep{
			Stage:   stage.name,
			Outcome: outcome,
			Reason:  reason,
		})
		switch outcome {
		case PolicyOutcomeAllow:
			decision := PolicyDecision{Allowed: true, Stage: stage.name, Reason: reason}
			for _, remaining := range stages[index+1:] {
				trace = append(trace, PolicyTraceStep{
					Stage:   remaining.name,
					Outcome: PolicyOutcomeSkipped,
					Reason:  "skipped after terminal decision at " + string(stage.name),
				})
			}
			trace = append(trace, PolicyTraceStep{
				Stage:   PolicyStageDefaultDeny,
				Outcome: PolicyOutcomeSkipped,
				Reason:  "skipped after terminal decision at " + string(stage.name),
			})
			return decision, trace, nil
		case PolicyOutcomeDeny:
			decision := denyDecision(stage.name, reason)
			for _, remaining := range stages[index+1:] {
				trace = append(trace, PolicyTraceStep{
					Stage:   remaining.name,
					Outcome: PolicyOutcomeSkipped,
					Reason:  "skipped after terminal decision at " + string(stage.name),
				})
			}
			trace = append(trace, PolicyTraceStep{
				Stage:   PolicyStageDefaultDeny,
				Outcome: PolicyOutcomeSkipped,
				Reason:  "skipped after terminal decision at " + string(stage.name),
			})
			return decision, trace, nil
		case PolicyOutcomeNoOpinion:
			continue
		default:
			return PolicyDecision{}, trace, fmt.Errorf("evaluate %s policy: invalid outcome %q", stage.name, outcome)
		}
	}

	decision := denyDecision(PolicyStageDefaultDeny, "no policy granted access")
	trace = append(trace, PolicyTraceStep{
		Stage:   PolicyStageDefaultDeny,
		Outcome: PolicyOutcomeDeny,
		Reason:  decision.Reason,
	})
	return decision, trace, nil
}

func denyDecision(stage PolicyStage, reason string) PolicyDecision {
	message := strings.TrimSpace(reason)
	if message == "" {
		message = "access denied"
	}
	return PolicyDecision{Allowed: false, Stage: stage, Reason: message}
}
