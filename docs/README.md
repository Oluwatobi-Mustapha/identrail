# Documentation Index

This index maps Identrail docs by operator, developer, security/compliance, and release workflows.

## Start here

- Enterprise quickstart: `enterprise-quickstart.md`
- Operator readiness handoff: `operator-readiness.md`
- Deployment runbook: `deploy-runbook.md`

## Operator track

- Deployment options:
  - `../deploy/README.md`
  - `deployment-anywhere.md`
  - `../deploy/docker/README.md`
  - `../deploy/kubernetes/README.md`
  - `../deploy/helm/README.md`
  - `../deploy/terraform/README.md`
- Day-2 operations:
  - `observability.md`
  - `troubleshooting.md`
  - `incident-response.md`
- Worker/scheduler behavior:
  - `worker.md`
  - `scheduler.md`

## Authorization and policy operations

- AuthZ operations runbook: `authz-operator-runbook.md`
- AuthZ rollout lifecycle: `authz-policy-rollout-runbook.md`
- Security hardening guidance: `security-hardening.md`

## API and developer track

- API contract (OpenAPI): `openapi-v1.yaml`
- Frontend topology (`web/` vs `site/`): `frontend-topology.md`
- Development workflow: `development-workflow.md`
- Testing strategy: `testing.md`
- Migrations strategy: `migrations.md`
- Artifact persistence notes: `persistence-artifacts.md`
- Repository exposure scanner: `repo-exposure.md`
- Configuration reference: `configuration-reference.md`

## Release and supply chain track

- Release pipeline: `release-pipeline.md`
- Supply chain trust artifacts: `supply-chain-trust.md`
- Versioning and support policy: `versioning-support-policy.md`
- Release qualification checklist: `v1_release_qualification.md`

## Security and governance track

- Threat model: `threat_model.md`
- Contributor trust scoring (Good Egg): `contributor-trust-scoring.md`
- Architecture decisions: `ADR.md`
- V1 scope baseline: `v1_scope_and_baseline.md`
- Security policy: `../SECURITY.md`
- Contributing guide: `../CONTRIBUTING.md`
- Code of conduct: `../CODE_OF_CONDUCT.md`

## identrail-reviewer track

- Reviewer overview: `identrail-reviewer/README.md`
- Ground-truth dataset guide: `identrail-reviewer/ground-truth-dataset.md`
- Reviewer operations runbook: `identrail-reviewer/operations-runbook.md`

## Architecture and provider internals

- Architecture overview: `architecture.md`
- AWS collector details: `aws-collector.md`
- AWS normalizer and graph: `aws-normalizer-graph.md`
- AWS risk engine: `aws-risk-engine.md`

## Historical phase records

- Phase 1: `phase-1.md`
- Phase 2: `phase-2.md`
- Phase 3: `phase-3.md`
- Phase 4: `phase-4.md`

## Supply chain implementation notes

- GUAC scaffold notes: `supply-chain-guac.md`
- Copilot autofix policy: `copilot-autofix.md`

## identrail-reviewer weekly implementation logs

- Week 1 foundation: `identrail-reviewer/week-1-foundation.md`
- Week 2 judgment engine: `identrail-reviewer/week-2-judgment-engine.md`
- Week 3 hardening: `identrail-reviewer/week-3-hardening.md`
- Week 4 rollout: `identrail-reviewer/week-4-rollout.md`
