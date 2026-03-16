# Aurelius

Aurelius is a production-grade machine identity security platform for discovering, mapping, analyzing, and securing workload identities across AWS, Kubernetes, and Azure.

Inspired by Marcus Aurelius' stoic governance, Aurelius emphasizes disciplined visibility, principled least privilege, and calm control under pressure. The platform helps cloud security and IAM teams answer critical questions:

- What machine identities exist across our environments?
- Which workloads can use them, and how?
- Where do overprivilege and escalation paths exist?
- Which identities are stale, ownerless, or risky?
- What is the blast radius, and how should we remediate it?

## Vision

Build the "iPhone of machine identity security": simple, intuitive, and elegant without sacrificing rigor. Aurelius is designed for incremental delivery with strong domain models, modular architecture, observability, idempotent processes, and thorough testing.

## Initial Scope

- v1: AWS-first discovery and risk analysis
- Extensible abstractions for Kubernetes and Azure
- Read-only integrations with least-privilege access
- Clear normalized graph model for identities, workloads, permissions, and findings
