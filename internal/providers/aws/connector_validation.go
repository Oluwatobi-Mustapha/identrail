package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	api "github.com/identrail/identrail/internal/api"
)

// ConnectionValidator validates AWS connector setup with read-only AWS calls.
type ConnectionValidator struct {
	region              string
	profile             string
	loadConfig          func(context.Context, string, string) (awsv2.Config, error)
	newAssumeRoleClient func(awsv2.Config) stsAssumeRoleAPI
	newIdentityClient   func(awsv2.Config) stsIdentityAPI
	newIAMClient        func(awsv2.Config) iamValidationAPI
}

var _ api.AWSConnectorValidator = (*ConnectionValidator)(nil)

type stsAssumeRoleAPI interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type stsIdentityAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type iamValidationAPI interface {
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// iamPermissionSimulationAPI is kept separate from iamValidationAPI so test
// adapters and older integrations that only implement the IAM metadata probes
// continue to work. The AWS SDK client implements both interfaces.
type iamPermissionSimulationAPI interface {
	SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

// NewConnectionValidator creates an AWS SDK-backed connector validator.
func NewConnectionValidator(region string, profile string) *ConnectionValidator {
	return &ConnectionValidator{
		region:     strings.TrimSpace(region),
		profile:    strings.TrimSpace(profile),
		loadConfig: loadAWSConnectorConfig,
		newAssumeRoleClient: func(cfg awsv2.Config) stsAssumeRoleAPI {
			return sts.NewFromConfig(cfg)
		},
		newIdentityClient: func(cfg awsv2.Config) stsIdentityAPI {
			return sts.NewFromConfig(cfg)
		},
		newIAMClient: func(cfg awsv2.Config) iamValidationAPI {
			return iam.NewFromConfig(cfg)
		},
	}
}

// ValidateAWSConnection assumes the configured connector role and checks scanner-critical read permissions.
func (v *ConnectionValidator) ValidateAWSConnection(ctx context.Context, request api.AWSConnectionValidationRequest) (api.AWSConnectionValidationResult, error) {
	region := firstNonEmptyString(strings.TrimSpace(request.Region), v.region, "us-east-1")
	loadConfig := v.loadConfig
	if loadConfig == nil {
		loadConfig = loadAWSConnectorConfig
	}
	baseCfg, err := loadConfig(ctx, region, v.profile)
	if err != nil {
		return api.AWSConnectionValidationResult{}, err
	}

	result := api.AWSConnectionValidationResult{
		RoleARN: strings.TrimSpace(request.RoleARN),
		Region:  region,
		PermissionChecks: []api.AWSConnectionPermissionCheck{{
			Name:    "sts:AssumeRole",
			Passed:  false,
			Message: "Role assumption has not completed.",
		}},
		Diagnostics: []api.AWSConnectionDiagnostic{},
	}

	assumeInput := &sts.AssumeRoleInput{
		RoleArn:         awsv2.String(result.RoleARN),
		RoleSessionName: awsv2.String(firstNonEmptyString(strings.TrimSpace(request.SessionName), "identrail-connector-validation")),
	}
	if externalID := strings.TrimSpace(request.ExternalID); externalID != "" {
		assumeInput.ExternalId = awsv2.String(externalID)
	}
	assumeClient := v.newAssumeRoleClient
	if assumeClient == nil {
		assumeClient = func(cfg awsv2.Config) stsAssumeRoleAPI { return sts.NewFromConfig(cfg) }
	}
	assumed, err := assumeClient(baseCfg).AssumeRole(ctx, assumeInput)
	if err != nil {
		result.PermissionChecks[0].Message = "AWS rejected sts:AssumeRole for the connector role."
		result.PermissionChecks[0].Remediation = "Update the role trust policy to allow this Identrail deployment to call sts:AssumeRole, and include the configured external ID condition when required."
		result.Diagnostics = append(result.Diagnostics, api.AWSConnectionDiagnostic{
			Code:        classifyAWSError(err, "aws_assume_role_failed"),
			Message:     "Unable to assume the AWS connector role.",
			Remediation: result.PermissionChecks[0].Remediation,
		})
		return result, nil
	}
	if assumed.Credentials == nil {
		result.PermissionChecks[0].Message = "AWS returned an AssumeRole response without credentials."
		result.PermissionChecks[0].Remediation = "Retry setup, then verify the role is assumable and not blocked by an organization SCP or permission boundary."
		result.Diagnostics = append(result.Diagnostics, api.AWSConnectionDiagnostic{
			Code:        "aws_assume_role_empty_credentials",
			Message:     "AssumeRole did not return temporary credentials.",
			Remediation: result.PermissionChecks[0].Remediation,
		})
		return result, nil
	}
	result.PermissionChecks[0].Passed = true
	result.PermissionChecks[0].Message = "Role assumption succeeded."
	result.PermissionChecks[0].Remediation = ""

	assumedCfg := baseCfg.Copy()
	assumedCfg.Credentials = credentials.NewStaticCredentialsProvider(
		awsv2.ToString(assumed.Credentials.AccessKeyId),
		awsv2.ToString(assumed.Credentials.SecretAccessKey),
		awsv2.ToString(assumed.Credentials.SessionToken),
	)

	identityClient := v.newIdentityClient
	if identityClient == nil {
		identityClient = func(cfg awsv2.Config) stsIdentityAPI { return sts.NewFromConfig(cfg) }
	}
	identity, err := identityClient(assumedCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		// AssumeRole already succeeded, so any failure of the follow-up
		// GetCallerIdentity call — AccessDenied, throttling, invalid token,
		// expired token, or otherwise — must not route the operator to
		// AssumeRole/trust-policy repair actions. AWS documents that
		// sts:GetCallerIdentity requires no permissions (it returns caller
		// info even under an explicit deny) and this validator supplies no
		// session policy to AssumeRole, so trust, session, SCP, and
		// permissions-boundary controls cannot be responsible for the outcome.
		// Classify every failure here as an identity-metadata anomaly so
		// guided repair points to credential/endpoint remediation regardless
		// of the underlying error subtype.
		result.Diagnostics = append(result.Diagnostics, api.AWSConnectionDiagnostic{
			Code:        "aws_identity_metadata_unexpected",
			Message:     "Unable to read caller identity metadata after assuming the connector role.",
			Remediation: "Retry validation; if the failure persists, check STS endpoint reachability from this deployment and confirm the assumed session credentials are intact — sts:GetCallerIdentity requires no permissions, so trust and session policies are not the cause.",
		})
		return result, nil
	}
	result.AccountID = strings.TrimSpace(awsv2.ToString(identity.Account))
	result.PrincipalARN = strings.TrimSpace(awsv2.ToString(identity.Arn))
	result.UserID = strings.TrimSpace(awsv2.ToString(identity.UserId))

	iamClient := v.newIAMClient
	if iamClient == nil {
		iamClient = func(cfg awsv2.Config) iamValidationAPI { return iam.NewFromConfig(cfg) }
	}
	validatedIAMClient := iamClient(assumedCfg)
	iamCheck := validateIAMReadPermissions(ctx, validatedIAMClient)
	if !iamCheck.Passed {
		result.Diagnostics = append(result.Diagnostics, api.AWSConnectionDiagnostic{
			Code:        classifyAWSError(iamCheckError(iamCheck), "aws_iam_read_failed"),
			Message:     "AWS IAM permission sanity check failed.",
			Remediation: iamCheck.Remediation,
		})
	}
	result.PermissionChecks = append(result.PermissionChecks, iamCheck)
	if simulator, ok := validatedIAMClient.(iamPermissionSimulationAPI); ok {
		scopeCheck, _ := validateIAMPermissionScope(ctx, simulator, result.RoleARN, region)
		if !scopeCheck.Passed {
			result.Diagnostics = append(result.Diagnostics, api.AWSConnectionDiagnostic{
				Code:        "aws_connector_permission_scope_incomplete",
				Message:     "The connector role does not have the complete read-only collector permission scope.",
				Remediation: scopeCheck.Remediation,
			})
		}
		result.PermissionChecks = append(result.PermissionChecks, scopeCheck)
	}

	return result, nil
}

const iamPermissionSimulationBatchSize = 100

func validateIAMPermissionScope(ctx context.Context, client iamPermissionSimulationAPI, roleARN string, region string) (api.AWSConnectionPermissionCheck, error) {
	check := api.AWSConnectionPermissionCheck{
		Name:    "aws:ReadOnlyCollectorScope",
		Passed:  true,
		Message: "The connector role grants every required read-only collector action.",
	}
	expected, err := expectedConnectorPermissionActions()
	if err != nil {
		check.Passed = false
		check.Message = "Identrail could not determine the required read-only collector permission scope."
		check.Remediation = "Refresh the Identrail connector policy definition, then validate the AWS connector again."
		return withIAMScopeCheckError(check, err), err
	}
	actions := make([]string, 0, len(expected))
	for action := range expected {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	missing := make(map[string]struct{})
	simulationContext := iamPermissionSimulationContext(region)
	simulationResources := iamPermissionSimulationResourceARNs(roleARN)
	for start := 0; start < len(actions); start += iamPermissionSimulationBatchSize {
		end := start + iamPermissionSimulationBatchSize
		if end > len(actions) {
			end = len(actions)
		}
		batch := actions[start:end]
		decisions := make(map[string]iamtypes.PolicyEvaluationDecisionType)
		marker := ""
		for {
			input := &iam.SimulatePrincipalPolicyInput{
				PolicySourceArn: awsv2.String(strings.TrimSpace(roleARN)),
				ActionNames:     batch,
				ResourceArns:    simulationResources,
				ContextEntries:  simulationContext,
				MaxItems:        awsv2.Int32(int32(len(batch))),
			}
			if marker != "" {
				input.Marker = awsv2.String(marker)
			}
			output, err := client.SimulatePrincipalPolicy(ctx, input)
			if err != nil {
				check.Passed = false
				check.Message = "The connector role permission scope could not be verified."
				check.Remediation = "Attach the current Identrail read-only collector policy (template 2.2.0), then validate the connector again. The policy must include iam:SimulatePrincipalPolicy and every action used by the AWS collectors."
				return withIAMScopeCheckError(check, err), err
			}
			if output != nil {
				for _, evaluation := range output.EvaluationResults {
					action := strings.ToLower(strings.TrimSpace(awsv2.ToString(evaluation.EvalActionName)))
					if action != "" {
						// A resource-scoped grant can deny the literal "*" probe
						// while allowing the representative role ARN. Preserve an
						// allowed result from any resource instead of letting a later
						// implicit deny overwrite it.
						if evaluation.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed || decisions[action] == iamtypes.PolicyEvaluationDecisionTypeAllowed {
							decisions[action] = iamtypes.PolicyEvaluationDecisionTypeAllowed
						} else if _, exists := decisions[action]; !exists {
							decisions[action] = evaluation.EvalDecision
						}
					}
				}
				if output.IsTruncated && strings.TrimSpace(awsv2.ToString(output.Marker)) != "" {
					marker = strings.TrimSpace(awsv2.ToString(output.Marker))
					continue
				}
			}
			break
		}
		for _, action := range batch {
			if decisions[strings.ToLower(action)] != iamtypes.PolicyEvaluationDecisionTypeAllowed {
				missing[action] = struct{}{}
			}
		}
	}
	if len(missing) == 0 {
		return check, nil
	}
	missingActions := make([]string, 0, len(missing))
	for action := range missing {
		missingActions = append(missingActions, action)
	}
	sort.Strings(missingActions)
	check.Passed = false
	check.Message = fmt.Sprintf("The connector role is missing %d required read-only collector action(s): %s.", len(missingActions), formatIAMActionSample(missingActions))
	check.Remediation = "Attach the current Identrail read-only collector policy (template 2.2.0), then validate the connector again. Do not add write permissions or weaken the external-ID trust condition."
	return check, nil
}

// iamPermissionSimulationResourceARNs probes both the account-wide wildcard
// and the configured connector role. The latter is a representative IAM
// resource that lets policies such as arn:aws:iam::<account>:role/* evaluate
// as allowed without weakening the permission check for genuinely missing
// actions.
func iamPermissionSimulationResourceARNs(roleARN string) []string {
	resources := []string{"*"}
	if trimmed := strings.TrimSpace(roleARN); strings.HasPrefix(trimmed, "arn:") {
		resources = append(resources, trimmed)
	}
	return resources
}

// iamPermissionSimulationContext mirrors the request context that the
// collector uses for regional AWS calls. Without aws:RequestedRegion, IAM
// evaluates a policy conditioned on that key as an implicit deny even when
// the role is authorized in the configured region.
func iamPermissionSimulationContext(region string) []iamtypes.ContextEntry {
	region = strings.TrimSpace(region)
	if region == "" {
		return nil
	}
	return []iamtypes.ContextEntry{{
		ContextKeyName:   awsv2.String("aws:RequestedRegion"),
		ContextKeyValues: []string{region},
		ContextKeyType:   iamtypes.ContextKeyTypeEnum("string"),
	}}
}

func formatIAMActionSample(actions []string) string {
	const sampleSize = 8
	if len(actions) <= sampleSize {
		return strings.Join(actions, ", ")
	}
	return strings.Join(actions[:sampleSize], ", ") + fmt.Sprintf(", and %d more", len(actions)-sampleSize)
}

func withIAMScopeCheckError(check api.AWSConnectionPermissionCheck, err error) api.AWSConnectionPermissionCheck {
	if err != nil {
		check.Message = strings.TrimSpace(check.Message + " (" + err.Error() + ")")
	}
	return check
}

func validateIAMReadPermissions(ctx context.Context, client iamValidationAPI) api.AWSConnectionPermissionCheck {
	check := api.AWSConnectionPermissionCheck{
		Name:    "iam:ReadRolePolicies",
		Passed:  true,
		Message: "IAM role and policy read permissions are available.",
	}
	roles, err := client.ListRoles(ctx, &iam.ListRolesInput{MaxItems: awsv2.Int32(1)})
	if err != nil {
		check.Passed = false
		check.Message = "The connector role cannot list IAM roles."
		check.Remediation = "Attach the Identrail read-only collector policy so the role can call iam:ListRoles and the IAM policy read APIs required for recurring scans."
		return withIAMCheckError(check, err)
	}
	if roles == nil || len(roles.Roles) == 0 {
		check.Message = "IAM role listing is available; no sample role exists for policy-read probing."
		return check
	}
	roleName := strings.TrimSpace(awsv2.ToString(roles.Roles[0].RoleName))
	if roleName == "" {
		check.Message = "IAM role listing is available; the sample role had no role name for policy-read probing."
		return check
	}
	inlinePolicies, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: awsv2.String(roleName), MaxItems: awsv2.Int32(1)})
	if err != nil {
		check.Passed = false
		check.Message = "The connector role cannot list inline policies for IAM roles."
		check.Remediation = "Allow iam:ListRolePolicies and iam:GetRolePolicy in the Identrail read-only collector policy."
		return withIAMCheckError(check, err)
	}
	if inlinePolicies != nil && len(inlinePolicies.PolicyNames) > 0 {
		policyName := strings.TrimSpace(inlinePolicies.PolicyNames[0])
		if policyName != "" {
			if _, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: awsv2.String(roleName), PolicyName: awsv2.String(policyName)}); err != nil {
				check.Passed = false
				check.Message = "The connector role cannot read inline IAM role policy documents."
				check.Remediation = "Allow iam:GetRolePolicy in the Identrail read-only collector policy."
				return withIAMCheckError(check, err)
			}
		}
	}
	attachedPolicies, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: awsv2.String(roleName), MaxItems: awsv2.Int32(1)})
	if err != nil {
		check.Passed = false
		check.Message = "The connector role cannot list managed policies attached to IAM roles."
		check.Remediation = "Allow iam:ListAttachedRolePolicies, iam:GetPolicy, and iam:GetPolicyVersion in the Identrail read-only collector policy."
		return withIAMCheckError(check, err)
	}
	if attachedPolicies != nil && len(attachedPolicies.AttachedPolicies) > 0 {
		policyARN := strings.TrimSpace(awsv2.ToString(attachedPolicies.AttachedPolicies[0].PolicyArn))
		if policyARN != "" {
			policy, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: awsv2.String(policyARN)})
			if err != nil {
				check.Passed = false
				check.Message = "The connector role cannot read managed IAM policy metadata."
				check.Remediation = "Allow iam:GetPolicy in the Identrail read-only collector policy."
				return withIAMCheckError(check, err)
			}
			versionID := defaultPolicyVersionID(policy)
			if versionID != "" {
				if _, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: awsv2.String(policyARN), VersionId: awsv2.String(versionID)}); err != nil {
					check.Passed = false
					check.Message = "The connector role cannot read managed IAM policy versions."
					check.Remediation = "Allow iam:GetPolicyVersion in the Identrail read-only collector policy."
					return withIAMCheckError(check, err)
				}
			}
		}
	}
	return check
}

func defaultPolicyVersionID(output *iam.GetPolicyOutput) string {
	if output == nil || output.Policy == nil {
		return ""
	}
	return strings.TrimSpace(awsv2.ToString(output.Policy.DefaultVersionId))
}

func withIAMCheckError(check api.AWSConnectionPermissionCheck, err error) api.AWSConnectionPermissionCheck {
	if err != nil {
		check.Message = strings.TrimSpace(check.Message + " (" + err.Error() + ")")
	}
	return check
}

func iamCheckError(check api.AWSConnectionPermissionCheck) error {
	message := strings.TrimSpace(check.Message)
	if message == "" {
		return nil
	}
	return errors.New(message)
}

func loadAWSConnectorConfig(ctx context.Context, region string, profile string) (awsv2.Config, error) {
	loadOptions := []func(*awscfg.LoadOptions) error{
		awscfg.WithRegion(region),
	}
	if trimmedProfile := strings.TrimSpace(profile); trimmedProfile != "" {
		loadOptions = append(loadOptions, awscfg.WithSharedConfigProfile(trimmedProfile))
	}
	cfg, err := awscfg.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return awsv2.Config{}, fmt.Errorf("load aws config: %w", err)
	}
	return cfg, nil
}

func classifyAWSError(err error, fallback string) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(strings.TrimSpace(apiErr.ErrorCode()))
		switch code {
		case "accessdenied", "accessdeniedexception", "unauthorizedoperation":
			return "aws_access_denied"
		case "invalidclienttokenid", "unrecognizedclientexception":
			return "aws_credentials_invalid"
		case "expiredtoken", "expiredtokenexception":
			return "aws_credentials_expired"
		case "throttling", "throttlingexception", "toomanyrequestsexception":
			return "aws_throttled"
		default:
			if code != "" {
				return "aws_" + strings.ReplaceAll(code, " ", "_")
			}
		}
	}
	return fallback
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
