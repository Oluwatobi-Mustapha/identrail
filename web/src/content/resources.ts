export type DocEntry = {
  title: string;
  description: string;
  href: string;
  tags: string[];
};

export type BlogPost = {
  title: string;
  slug: string;
  description: string;
  category: string;
  readTime: string;
  summary: string;
  sections: {
    heading: string;
    paragraphs: string[];
    bullets?: string[];
  }[];
  identrailFit: string[];
  references: {
    label: string;
    href: string;
  }[];
};

export type FaqItem = {
  question: string;
  answer: string;
};

export const HOME_FAQ_ITEMS: FaqItem[] = [
  {
    question: 'Is the scan read-only?',
    answer:
      'Yes. Identrail discovery connectors are built for read-only collection of identity and trust-path metadata. You control write actions separately through staged policy workflows.'
  },
  {
    question: 'How does Identrail access AWS, Kubernetes, and GitHub data?',
    answer:
      'Identrail uses least-privilege service principals, IAM roles, and API tokens to collect machine identity metadata from AWS IAM, Kubernetes RBAC and service accounts, plus repository and workflow signals from Git providers.'
  },
  {
    question: 'What data is stored?',
    answer:
      'By default, Identrail stores graph metadata needed for trust-path analysis, findings, and remediation history. Sensitive values such as raw secrets are not required for core trust-path mapping.'
  },
  {
    question: 'Can we self-host?',
    answer:
      'Yes. The open-source core is designed for self-hosted evaluation and production environments. Teams can later adopt hosted SaaS or enterprise deployment models without re-platforming.'
  },
  {
    question: 'How does policy simulation avoid breaking production?',
    answer:
      'Policy simulation shows which workloads and trust paths would be affected before enforcement. Teams can roll out in stages, monitor impact, and use rollback controls if needed.'
  },
  {
    question: 'What integrations are supported?',
    answer:
      'Identrail supports AWS IAM, Kubernetes identities and RBAC, OIDC trust relationships, and Git-based repository/workflow telemetry. Enterprise workflows can connect ticketing and operational controls.'
  }
];

export const BLOG_POSTS: BlogPost[] = [
  {
    title: 'Machine Identity Security in 2026: A Practical Operating Model',
    slug: 'machine-identity-security-operating-model-2026',
    description:
      'The frameworks platform and security teams use to discover, prioritize, and control machine trust paths in production.',
    category: 'Machine Identity Security',
    readTime: '10 min',
    summary:
      'Machine identities now dominate cloud access. This guide lays out an operating model teams can run weekly, not yearly, to reduce real trust-path risk.',
    sections: [
      {
        heading: 'Why this problem keeps getting worse',
        paragraphs: [
          'Most teams now run thousands of machine identities across AWS, Kubernetes, CI, and automation. The challenge is not creating identities. The challenge is preventing trust drift across systems that evolve every sprint.',
          'When security reviews are done as isolated IAM or RBAC checks, organizations miss how permissions chain together. Attack paths are graph problems, not policy-file problems.'
        ]
      },
      {
        heading: 'A practical operating model security and platform teams can share',
        paragraphs: [
          'The model that works in practice has four loops: discovery, trust-path mapping, risk ranking, and rollout-safe control changes. Each loop should run continuously with clear ownership and evidence outputs.',
          'This aligns with NIST zero trust guidance: no implicit trust, continuous verification, and policy decisions based on live context.'
        ],
        bullets: [
          'Discovery: maintain a current machine-identity inventory across cloud and cluster layers.',
          'Mapping: model assumable paths and resource reachability, not only direct permissions.',
          'Prioritization: rank findings by exploitable blast radius and business impact.',
          'Enforcement: stage policy hardening with simulation and rollback controls.'
        ]
      },
      {
        heading: 'How to measure progress without vanity metrics',
        paragraphs: [
          'Metrics like tickets closed or policies reviewed are activity metrics. They do not prove reduced risk. Strong programs track: critical trust paths removed, time-to-remediate high-impact paths, and least-privilege coverage for production identities.',
          'If those three metrics improve quarter over quarter, posture is improving in ways that incident response teams and leadership can both validate.'
        ]
      }
    ],
    identrailFit: [
      'Identrail maintains a graph-based view of machine identities and trust relationships across AWS and Kubernetes.',
      'It helps teams prioritize reachable high-impact paths instead of broad noisy findings.',
      'Its rollout-safe workflow supports simulation and staged remediation before production enforcement.'
    ],
    references: [
      {
        label: 'NIST SP 800-207 Zero Trust Architecture',
        href: 'https://csrc.nist.gov/pubs/sp/800/207/final'
      },
      {
        label: 'CISA Zero Trust Maturity Model',
        href: 'https://www.cisa.gov/zero-trust-maturity-model'
      },
      {
        label: 'SPIFFE/SPIRE Concepts',
        href: 'https://spiffe.io/docs/latest/spire-about/spire-concepts/'
      }
    ]
  },
  {
    title: 'AWS NHI Security: 14 Misconfigurations That Expand Blast Radius',
    slug: 'aws-nhi-security-misconfigurations',
    description:
      'A field guide to overprivileged IAM role chains, cross-account assumptions, and practical remediation patterns.',
    category: 'AWS Security',
    readTime: '8 min',
    summary:
      'Most AWS machine-identity incidents trace back to misconfiguration, not exotic exploitation. This guide prioritizes the 14 patterns that expand blast radius fastest.',
    sections: [
      {
        heading: 'Why AWS identity incidents repeat the same root causes',
        paragraphs: [
          'In many breaches, the initial foothold is a compromised workload role or leaked automation credential. Escalation happens because trust and permission boundaries were wider than intended.',
          'The recurring issue is not missing capability. AWS already ships strong IAM controls. The gap is operational rigor around validation, simulation, and lifecycle hygiene.'
        ]
      },
      {
        heading: 'The highest-impact misconfiguration patterns',
        paragraphs: [
          'The riskiest patterns include wildcard action scopes, wildcard resource scopes, permissive AssumeRole trust policies, stale high-privilege roles, and weak cross-account constraints.',
          'Teams should also treat process flaws as misconfiguration: policy changes pushed without Access Analyzer checks or simulation gates are effectively unreviewed trust changes.'
        ],
        bullets: [
          'Broad role policies (`Action: *`, `Resource: *`) in production contexts.',
          'Trust policies with unnecessary principals and missing conditions.',
          'Long-lived access keys where role-based temporary credentials are possible.',
          'No pre-merge validation or pre-release policy simulation.'
        ]
      },
      {
        heading: 'A remediation order that avoids outages',
        paragraphs: [
          'First, establish visibility and quality gates. Then tighten high-risk trust paths in staged batches by environment and service criticality.',
          'This sequence lowers security risk while preserving release reliability, which is usually where IAM hardening projects fail.'
        ]
      }
    ],
    identrailFit: [
      'Identrail exposes cross-account trust chains and privilege paths, not just isolated policy findings.',
      'It prioritizes remediation by reachable impact, helping teams fix what actually reduces blast radius.',
      'Simulation-first rollout support reduces production disruption during IAM hardening.'
    ],
    references: [
      {
        label: 'AWS IAM Security Best Practices',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
      },
      {
        label: 'IAM Access Analyzer Policy Validation',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html'
      },
      {
        label: 'IAM Policy Simulator',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html'
      }
    ]
  },
  {
    title: 'Kubernetes Machine Identity: RBAC Risk Paths You Can Actually Fix',
    slug: 'kubernetes-machine-identity-rbac-risk-paths',
    description:
      'How to map service account privilege escalations and implement rollout-safe policy tightening without downtime.',
    category: 'Kubernetes Security',
    readTime: '9 min',
    summary:
      'Kubernetes identity risk is usually a chain of small grants. This article focuses on practical RBAC and service-account fixes that work in live clusters.',
    sections: [
      {
        heading: 'Why RBAC reviews miss real escalation',
        paragraphs: [
          'Teams often audit roles one by one, but escalation risk typically emerges from combinations: service accounts, bindings, token behavior, admission gaps, and namespace boundaries.',
          'A permission that looks harmless in isolation can become dangerous when chained with secret access, pod creation, or control-plane adjacent actions.'
        ]
      },
      {
        heading: 'What to fix first in production',
        paragraphs: [
          'Start by reducing default service-account privilege and reviewing cluster-wide bindings. Then enforce admission controls for unsafe RBAC changes and ensure API audit logs support identity-path analysis.',
          'This order gives immediate reduction in exploitability without attempting an all-at-once RBAC rewrite.'
        ],
        bullets: [
          'Scope service accounts to workload function and environment.',
          'Remove unnecessary ClusterRoleBinding entries with broad authority.',
          'Apply validating admission controls for risky RBAC mutations.',
          'Enable and tune Kubernetes audit logs for authorization visibility.'
        ]
      },
      {
        heading: 'Rollout without breaking workloads',
        paragraphs: [
          'Use monitor-first, then canary policy tightening by namespace tier. Keep rollback paths explicit and tested. Security controls only stick when platform reliability is preserved.',
          'The goal is progressive reduction of exploitable paths, not perfect policy in one release.'
        ]
      }
    ],
    identrailFit: [
      'Identrail maps service-account privilege paths with cross-layer trust context.',
      'It helps teams target exploitable escalation chains for staged remediation.',
      'Simulation and evidence outputs support safer RBAC tightening in production.'
    ],
    references: [
      {
        label: 'Kubernetes RBAC Authorization',
        href: 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/'
      },
      {
        label: 'Kubernetes Service Accounts',
        href: 'https://kubernetes.io/docs/concepts/security/service-accounts/'
      },
      {
        label: 'Kubernetes Auditing',
        href: 'https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/'
      }
    ]
  },
  {
    title: 'From Secrets Sprawl to Signal: Building a Repo Exposure Program',
    slug: 'repo-exposure-program-machine-identities',
    description:
      'How platform teams operationalize git credential leak findings and connect them to real machine identity risk.',
    category: 'Software Supply Chain',
    readTime: '7 min',
    summary:
      'Secret scanners are detection engines, not response programs. This article shows how to convert leak alerts into measurable containment and risk reduction.',
    sections: [
      {
        heading: 'Why secret alerts become noise',
        paragraphs: [
          'Many teams have scanning enabled but still struggle with credential incidents. The gap is triage context: validity, privilege, reachable systems, and owner accountability are often unknown at alert time.',
          'Without context, teams prioritize by regex confidence or timestamp, not exploitability.'
        ]
      },
      {
        heading: 'Design a program, not just a scan job',
        paragraphs: [
          'A resilient exposure program links detection to classification, revoke/rotate automation, clear ownership routing, and prevention feedback into delivery pipelines.',
          'The most useful KPI is high-impact mean time to containment, not total alerts closed.'
        ],
        bullets: [
          'Classify leaked credentials by active access and environment criticality.',
          'Automate containment runbooks for common credential classes.',
          'Route response with explicit service owner SLAs.',
          'Feed recurrent root causes into SDLC guardrails.'
        ]
      },
      {
        heading: 'Tie credential hygiene to machine identity posture',
        paragraphs: [
          'Credential leaks are not only repository hygiene issues. They are machine identity risk issues because leaked credentials often map directly to trust paths in cloud environments.',
          'Connecting code exposure to live identity blast radius produces better prioritization and faster containment.'
        ]
      }
    ],
    identrailFit: [
      'Identrail correlates repository exposure findings with machine-identity trust paths.',
      'It helps teams separate high-impact leaks from low-risk noise quickly.',
      'Shared evidence improves coordination between security and platform responders.'
    ],
    references: [
      {
        label: 'GitHub Secret Scanning',
        href: 'https://docs.github.com/code-security/secret-scanning/about-secret-scanning'
      },
      {
        label: 'NIST SSDF SP 800-218',
        href: 'https://csrc.nist.gov/publications/detail/sp/800-218/final'
      },
      {
        label: 'CISA Software Supply Chain Recommended Practices',
        href: 'https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain-recommended-practices-guide-customers-and'
      }
    ]
  },
  {
    title: 'Open-Core vs Closed Platforms in Machine Identity Security',
    slug: 'open-core-vs-closed-machine-identity-security',
    description:
      'A transparent analysis of architecture, control, and TCO tradeoffs for enterprise buyers evaluating vendors.',
    category: 'Buying Guide',
    readTime: '6 min',
    summary:
      'This is less a feature battle and more an operating-model decision. The right choice depends on control requirements, team capacity, and long-term portability.',
    sections: [
      {
        heading: 'What buyers often miss',
        paragraphs: [
          'Platform selection is frequently optimized for fast onboarding instead of long-term operational control. That creates lock-in and architectural friction as requirements evolve.',
          'Machine identity security touches cloud, platform engineering, compliance, and incident response. Vendor choices should be tested against those real workflows.'
        ]
      },
      {
        heading: 'Evaluation criteria that survive beyond pilot phase',
        paragraphs: [
          'Strong evaluations check transparency of risk logic, quality of trust-path explainability, rollout safety controls, and audit evidence portability. Teams should also assess migration cost if strategy changes after year one.',
          'Short demos rarely expose these factors. Structured scorecards and scenario-based testing do.'
        ],
        bullets: [
          'Can the platform explain exactly why a path is risky?',
          'Can controls be tuned without brittle custom glue?',
          'Can evidence be exported for audit and executive reporting?',
          'Can deployment mode evolve without re-platforming?'
        ]
      },
      {
        heading: 'Use objective ecosystem signals',
        paragraphs: [
          'Complement product evaluation with objective ecosystem indicators such as supply-chain framework alignment and project security health metrics.',
          'These signals do not replace engineering validation, but they improve procurement decisions and reduce narrative bias.'
        ]
      }
    ],
    identrailFit: [
      'Identrail provides open-core transparency with enterprise-ready control pathways.',
      'Teams can prove value quickly, then scale deployment model without changing the operating workflow.',
      'The platform is designed for shared security and platform ownership from day one.'
    ],
    references: [
      {
        label: 'SLSA Framework',
        href: 'https://slsa.dev/'
      },
      {
        label: 'OpenSSF Scorecard',
        href: 'https://scorecard.dev/'
      },
      {
        label: 'NIST SP 800-207',
        href: 'https://csrc.nist.gov/pubs/sp/800/207/final'
      }
    ]
  },
  {
    title: 'How to Prove Least Privilege for Non-Human Identities to Auditors',
    slug: 'least-privilege-evidence-for-non-human-identities',
    description:
      'Generate evidence for SOC 2 and ISO 27001 with trust graph snapshots, policy simulations, and remediation trails.',
    category: 'Compliance',
    readTime: '11 min',
    summary:
      'Least privilege claims fail audits when evidence is static or incomplete. This article details an evidence model auditors can actually validate.',
    sections: [
      {
        heading: 'Audit reality: evidence over intent',
        paragraphs: [
          'Saying least privilege is enforced does not satisfy audit requirements. Auditors expect evidence of current access state, review process, exceptions, and remediation effectiveness.',
          'For non-human identities, this is especially important because privilege drift can happen rapidly through pipeline and infrastructure changes.'
        ]
      },
      {
        heading: 'Build an evidence package that holds up',
        paragraphs: [
          'An effective package includes point-in-time trust snapshots, trend lines for high-risk path reduction, policy change histories, and exception registers with owner plus expiry.',
          'Evidence must be reproducible and linked to control operation, not assembled as static narrative near audit deadlines.'
        ],
        bullets: [
          'Current machine-identity inventory and effective permission view.',
          'High-impact trust paths with treatment decisions and timestamps.',
          'Policy change logs with validation and simulation outcomes.',
          'Exception records with owner, expiration, and closure state.'
        ]
      },
      {
        heading: 'Align to SOC 2 and ISO 27001 without heavy manual overhead',
        paragraphs: [
          'Teams that continuously collect evidence reduce audit friction significantly. Automated evidence generation lowers manual prep and improves confidence in control effectiveness.',
          'The practical objective is audit-ready operations, not audit-season document reconstruction.'
        ]
      }
    ],
    identrailFit: [
      'Identrail provides trust-graph snapshots and remediation trails suitable for audit evidence.',
      'It tracks risk-path reduction over time to support least-privilege control claims.',
      'Security, platform, and compliance teams can review a shared evidence source.'
    ],
    references: [
      {
        label: 'AICPA SOC 2 Resources',
        href: 'https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2'
      },
      {
        label: 'ISO/IEC 27001',
        href: 'https://www.iso.org/standard/27001'
      },
      {
        label: 'NIST Cybersecurity Framework 2.0 Guide',
        href: 'https://www.nist.gov/publications/nist-cybersecurity-framework-20-resource-overview-guide'
      }
    ]
  },
  {
    title: 'Designing Rollout-Safe Authorization Controls for Platform Teams',
    slug: 'rollout-safe-authorization-controls',
    description:
      'Staged policy rollouts, simulation gates, and kill-switch patterns that reduce authz outage risk in production.',
    category: 'Platform Engineering',
    readTime: '8 min',
    summary:
      'Authorization hardening often fails because rollout safety is underdesigned. This article presents a release-engineering model for policy controls.',
    sections: [
      {
        heading: 'Why hardening initiatives trigger outages',
        paragraphs: [
          'Many teams implement strict policies in one step and discover production breakage after deployment. That erodes trust between security and platform teams.',
          'The underlying issue is process design: policy changes are treated as simple config updates instead of high-impact production releases.'
        ]
      },
      {
        heading: 'A rollout-safe authorization pattern',
        paragraphs: [
          'Use simulation first, monitor mode second, canary deployment third, and gated expansion with tested rollback controls. This pattern mirrors safe software delivery principles.',
          'Teams should define ownership for each gate, including who can halt rollout and who can trigger rollback.'
        ],
        bullets: [
          'Run pre-enforcement simulation against representative workloads.',
          'Canary policies by environment or service tier.',
          'Use reliability gates (error rate, deny rate, SLO impact) before expansion.',
          'Maintain explicit rollback and kill-switch procedures.'
        ]
      },
      {
        heading: 'Make security and reliability shared outcomes',
        paragraphs: [
          'When teams can see policy impact before full enforcement, security controls become easier to adopt and sustain.',
          'The target state is predictable, low-drama hardening with measurable risk reduction.'
        ]
      }
    ],
    identrailFit: [
      'Identrail supports simulation-first policy hardening and staged rollout controls.',
      'It surfaces likely impact before production-wide enforcement decisions.',
      'Teams can improve least privilege while preserving platform reliability.'
    ],
    references: [
      {
        label: 'OPA Policy Testing',
        href: 'https://www.openpolicyagent.org/docs/latest/policy-testing/'
      },
      {
        label: 'Kubernetes Admission Webhook Good Practices',
        href: 'https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/'
      },
      {
        label: 'Google SRE Canarying Releases',
        href: 'https://sre.google/workbook/canarying-releases/'
      }
    ]
  },
  {
    title: 'Trust Graphs for Security Leaders: What to Measure and Why',
    slug: 'trust-graph-metrics-for-security-leaders',
    description:
      'Metrics that connect machine identity posture improvements to incident reduction and executive risk reporting.',
    category: 'Security Leadership',
    readTime: '7 min',
    summary:
      'Leadership reporting improves when metrics reflect reachable risk, not control activity. Trust graphs provide a strong model for decision-grade security metrics.',
    sections: [
      {
        heading: 'Move beyond activity dashboards',
        paragraphs: [
          'Security dashboards often emphasize counts: alerts, tickets, policies touched. These metrics are operationally useful but weak for executive risk decisions.',
          'Leaders need to know whether high-impact exposure is decreasing and how quickly the organization can reduce newly discovered risk.'
        ]
      },
      {
        heading: 'Metrics that create better prioritization',
        paragraphs: [
          'A trust-graph model supports metrics like critical path count to crown-jewel systems, mean time to remediate top-tier identity exposure, least-privilege coverage for production identities, and policy rollout failure rate.',
          'These metrics connect engineering work directly to incident likelihood and business impact.'
        ],
        bullets: [
          'Number of critical trust paths to sensitive systems.',
          'Time-to-remediate high-impact machine-identity risk.',
          'Least-privilege coverage across production machine identities.',
          'Authorization rollout failure and recovery trends.'
        ]
      },
      {
        heading: 'Use external frameworks for reporting context',
        paragraphs: [
          'Framework mapping can improve communication quality. ATT&CK cloud coverage can frame detection posture, while DORA delivery metrics can indicate whether controls are improving safely and sustainably.',
          'The goal is board-level clarity without flattening technical nuance.'
        ]
      }
    ],
    identrailFit: [
      'Identrail turns identity relationships into measurable trust-path risk metrics.',
      'It helps leadership connect remediation activity to reduced blast radius and incident exposure.',
      'Evidence outputs are structured for both engineering and executive reporting workflows.'
    ],
    references: [
      {
        label: 'MITRE ATT&CK Cloud Matrix',
        href: 'https://attack.mitre.org/matrices/enterprise/cloud/'
      },
      {
        label: 'DORA Metrics Guide',
        href: 'https://dora.dev/guides/dora-metrics/'
      },
      {
        label: 'CISA Zero Trust Maturity Model',
        href: 'https://www.cisa.gov/zero-trust-maturity-model'
      }
    ]
  }
];

export const DOC_ENTRIES: DocEntry[] = [
  {
    title: 'Quickstart on Docker',
    description: 'Deploy Identrail locally in under 10 minutes using Docker Compose.',
    href: 'https://github.com/identrail/identrail/blob/main/deploy/docker/README.md',
    tags: ['quickstart', 'docker', 'self-hosted']
  },
  {
    title: 'Deploy Anywhere Runbook',
    description: 'Production deployment guidance for Kubernetes, Helm, Terraform, and systemd.',
    href: 'https://github.com/identrail/identrail/blob/main/docs/deployment-anywhere.md',
    tags: ['deployment', 'kubernetes', 'terraform']
  },
  {
    title: 'Architecture Deep Dive',
    description: 'Understand ingestion pipelines, trust graph construction, and authorization controls.',
    href: 'https://github.com/identrail/identrail/blob/main/docs/architecture.md',
    tags: ['architecture', 'graph', 'platform']
  },
  {
    title: 'AWS Collector',
    description: 'Collector configuration, permissions, and scaling tips for IAM role and policy discovery.',
    href: 'https://github.com/identrail/identrail/blob/main/docs/aws-collector.md',
    tags: ['aws', 'iam', 'collector']
  },
  {
    title: 'Repo Exposure Scanner',
    description: 'Scan Git repositories for credential leaks and machine identity exposure patterns.',
    href: 'https://github.com/identrail/identrail/blob/main/docs/repo-exposure.md',
    tags: ['git', 'secrets', 'scanner']
  },
  {
    title: 'Security Hardening Guide',
    description: 'Hardening checklist, supply chain controls, and incident response guidance.',
    href: 'https://github.com/identrail/identrail/blob/main/docs/security-hardening.md',
    tags: ['security', 'hardening', 'operations']
  }
];
