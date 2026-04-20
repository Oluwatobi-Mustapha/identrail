import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation } from 'react-router-dom';
import { SafeLink } from './components/SafeLink';

type SeoConfig = {
  title: string;
  description: string;
  path: string;
  keywords?: string;
  schemaType?: 'WebPage' | 'Product' | 'Article' | 'AboutPage';
};

type DocEntry = {
  title: string;
  description: string;
  href: string;
  tags: string[];
};

type BlogPost = {
  title: string;
  slug: string;
  description: string;
  category: string;
  readTime: string;
};

declare global {
  interface Window {
    gtag?: (...args: unknown[]) => void;
    posthog?: {
      capture: (event: string, properties?: Record<string, unknown>) => void;
    };
    identrailAB?: {
      variant?: string;
    };
  }
}

const SITE_URL = 'https://identrail.com';
const GITHUB_REPO = 'https://github.com/identrail/identrail';
const DOCS_REPO = 'https://github.com/identrail/identrail/tree/main/docs';
const DISCORD_URL = 'https://discord.gg/7jSUSnQC';
const LINKEDIN_URL = 'https://www.linkedin.com/company/identrail/';
const X_URL = 'https://x.com/identrail';
const CALENDLY_URL = 'https://calendly.com/identrail/15min';

const NAV_LINKS = [
  { to: '/solutions', label: 'Solutions' },
  { to: '/pricing', label: 'Pricing' },
  { to: '/demo', label: 'Demo' },
  { to: '/docs', label: 'Docs' },
  { to: '/blog', label: 'Blog' }
] as const;

const TRUSTED_LOGOS = [
  'Fortune 50 Financial Services',
  'Global Commerce Platform',
  'Top 3 Cloud-Native Fintech',
  'Enterprise Healthcare Provider',
  'Public Sector Infrastructure Team'
] as const;

const BLOG_POSTS: BlogPost[] = [
  {
    title: 'Machine Identity Security in 2026: A Practical Operating Model',
    slug: 'machine-identity-security-operating-model-2026',
    description:
      'The frameworks platform and security teams use to discover, prioritize, and control machine trust paths in production.',
    category: 'Machine Identity Security',
    readTime: '10 min'
  },
  {
    title: 'AWS NHI Security: 14 Misconfigurations That Expand Blast Radius',
    slug: 'aws-nhi-security-misconfigurations',
    description:
      'A field guide to overprivileged IAM role chains, cross-account assumptions, and practical remediation patterns.',
    category: 'AWS Security',
    readTime: '8 min'
  },
  {
    title: 'Kubernetes Machine Identity: RBAC Risk Paths You Can Actually Fix',
    slug: 'kubernetes-machine-identity-rbac-risk-paths',
    description:
      'How to map service account privilege escalations and implement rollout-safe policy tightening without downtime.',
    category: 'Kubernetes Security',
    readTime: '9 min'
  },
  {
    title: 'From Secrets Sprawl to Signal: Building a Repo Exposure Program',
    slug: 'repo-exposure-program-machine-identities',
    description:
      'How platform teams operationalize git credential leak findings and connect them to real machine identity risk.',
    category: 'Software Supply Chain',
    readTime: '7 min'
  },
  {
    title: 'Open-Core vs Closed Platforms in Machine Identity Security',
    slug: 'open-core-vs-closed-machine-identity-security',
    description:
      'A transparent analysis of architecture, control, and TCO tradeoffs for enterprise buyers evaluating vendors.',
    category: 'Buying Guide',
    readTime: '6 min'
  },
  {
    title: 'How to Prove Least Privilege for Non-Human Identities to Auditors',
    slug: 'least-privilege-evidence-for-non-human-identities',
    description:
      'Generate evidence for SOC 2 and ISO 27001 with trust graph snapshots, policy simulations, and remediation trails.',
    category: 'Compliance',
    readTime: '11 min'
  },
  {
    title: 'Designing Rollout-Safe Authorization Controls for Platform Teams',
    slug: 'rollout-safe-authorization-controls',
    description:
      'Staged policy rollouts, simulation gates, and kill-switch patterns that reduce authz outage risk in production.',
    category: 'Platform Engineering',
    readTime: '8 min'
  },
  {
    title: 'Trust Graphs for Security Leaders: What to Measure and Why',
    slug: 'trust-graph-metrics-for-security-leaders',
    description:
      'Metrics that connect machine identity posture improvements to incident reduction and executive risk reporting.',
    category: 'Security Leadership',
    readTime: '7 min'
  }
];

const DOC_ENTRIES: DocEntry[] = [
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

const SOCIAL_QUOTES = [
  {
    quote:
      'Identrail mapped over 12,000 machine trust paths in week one and gave us a clear remediation queue.',
    name: 'Principal Cloud Security Engineer',
    company: 'Global Payments Company'
  },
  {
    quote:
      'We reduced privileged service account risk by 87% without breaking production rollouts.',
    name: 'Director of Platform Security',
    company: 'Enterprise SaaS Provider'
  },
  {
    quote:
      'The open-core model let us self-host quickly while preparing enterprise controls for procurement.',
    name: 'VP Security Engineering',
    company: 'Large Healthcare Network'
  }
] as const;

const DIFFERENTIATION_ROWS = [
  {
    area: 'Core Platform Access',
    identrail: 'Open-source core with transparent architecture and self-host option',
    alternatives: 'Closed source only; limited implementation transparency'
  },
  {
    area: 'Trust Graph Explainability',
    identrail: 'Interactive trust-path evidence with policy and resource context',
    alternatives: 'High-level findings with limited path-level explainability'
  },
  {
    area: 'Rollout Safety',
    identrail: 'Policy simulation + staged controls + kill switch in one workflow',
    alternatives: 'Policy changes often require parallel tooling and manual validation'
  },
  {
    area: 'Developer Experience',
    identrail: 'GitHub-first docs, API-first workflows, contributor-friendly roadmap',
    alternatives: 'Vendor-led delivery model with slower dev-team iteration'
  }
] as const;

const FEATURE_ROWS = [
  {
    capability: 'AWS IAM role discovery',
    openSource: 'Included',
    pro: 'Included',
    enterprise: 'Included'
  },
  {
    capability: 'Kubernetes RBAC and service account mapping',
    openSource: 'Included',
    pro: 'Included',
    enterprise: 'Included'
  },
  {
    capability: 'Git repository credential exposure scanning',
    openSource: 'Basic detectors',
    pro: 'Advanced signatures + workflows',
    enterprise: 'Advanced + custom signatures'
  },
  {
    capability: 'Trust graph explorer',
    openSource: 'Included',
    pro: 'Included + hosted query acceleration',
    enterprise: 'Included + custom graph retention'
  },
  {
    capability: 'Hosted SaaS',
    openSource: 'No',
    pro: 'Yes',
    enterprise: 'Yes'
  },
  {
    capability: 'SSO/SAML + SCIM',
    openSource: 'No',
    pro: 'SAML',
    enterprise: 'SAML + SCIM + advanced controls'
  },
  {
    capability: 'Data residency options',
    openSource: 'Self-host control',
    pro: 'US + EU',
    enterprise: 'Regional + private tenancy'
  },
  {
    capability: 'Support and SLAs',
    openSource: 'Community',
    pro: 'Business-hour support',
    enterprise: '24/7, named TAM, custom SLA'
  }
] as const;

const FEATURE_DEEP_PAGES = [
  {
    slug: 'aws',
    navLabel: 'AWS',
    heroTitle: 'AWS IAM security with path-level explainability',
    description:
      'Discover roles, trust policies, and cross-account assumptions in one graph so teams can reduce IAM blast radius with confidence.',
    bullets: [
      'Map every role assumption chain and transitive trust path across accounts',
      'Prioritize overprivileged IAM paths by reachable sensitive resources',
      'Preview trust-policy hardening before production rollout'
    ],
    outcomes: [
      'Faster IAM triage for security engineering teams',
      'Clear remediation stories for platform owners',
      'Reduced high-risk cross-account pathways'
    ]
  },
  {
    slug: 'kubernetes',
    navLabel: 'Kubernetes',
    heroTitle: 'Kubernetes machine identity visibility beyond RBAC tables',
    description:
      'Correlate service accounts, tokens, roles, and bindings with cloud federation context to find exploitable privilege paths.',
    bullets: [
      'Trace namespace and cluster-level escalation paths from service accounts',
      'Understand cluster-to-cloud trust bridges through OIDC federation',
      'Simulate RBAC hardening changes to avoid workload breakage'
    ],
    outcomes: [
      'Lower RBAC drift and accidental privilege growth',
      'Safer service account governance in production clusters',
      'Faster root-cause analysis during identity incidents'
    ]
  },
  {
    slug: 'git-scanner',
    navLabel: 'Git Scanner',
    heroTitle: 'Repository exposure scanning tied directly to machine identity risk',
    description:
      'Catch leaked credentials and dangerous identity patterns in repositories, then connect each finding to live trust-path impact.',
    bullets: [
      'Scan historical and incoming commits for credentials and risky configs',
      'Tune detection signatures for organization-specific token patterns',
      'Link findings to trust graph nodes for prioritized remediation'
    ],
    outcomes: [
      'Earlier credential leak detection and containment',
      'Lower false-priority triage load for security teams',
      'Stronger software-to-cloud identity governance'
    ]
  },
  {
    slug: 'trust-graph',
    navLabel: 'Trust Graph',
    heroTitle: 'Interactive Trust Graph for machine identity attack-path analysis',
    description:
      'Visualize identity relationships end-to-end, inspect every edge, and answer exactly how a machine principal can reach sensitive resources.',
    bullets: [
      'Inspect path evidence with policy, principal, and resource context',
      'Highlight blast-radius expansion from any identity node',
      'Export remediation stories for engineering execution'
    ],
    outcomes: [
      'Common operating picture across security and platform teams',
      'Higher-confidence prioritization of real exposure chains',
      'Faster decision-making for authorization change control'
    ]
  }
] as const;

const SOLUTION_DEEP_PAGES = [
  {
    slug: 'aws',
    navLabel: 'AWS',
    heroTitle: 'Solution for AWS security teams',
    description:
      'Reduce IAM blast radius with explainable trust paths, prioritized exposure queues, and rollout-safe least-privilege workflows.',
    bullets: [
      'Continuously discover machine identities and trust relationships in AWS',
      'Detect high-impact assumption chains and overprivileged role paths',
      'Coordinate remediation with platform teams through shared graph evidence'
    ],
    outcomes: [
      '60-90% reduction in overprivileged IAM role exposure',
      'Faster incident-response triage for identity pathways',
      'Audit-ready visibility into trust policy changes'
    ]
  },
  {
    slug: 'kubernetes',
    navLabel: 'Kubernetes',
    heroTitle: 'Solution for Kubernetes platform teams',
    description:
      'Control service-account and RBAC risk in production clusters without slowing down release velocity.',
    bullets: [
      'Expose hidden service-account privilege escalation paths',
      'Correlate RBAC risk with cloud permissions and federated trust',
      'Roll out safer RBAC policy controls with staged validation'
    ],
    outcomes: [
      'Reduced cluster authorization incidents',
      'More predictable least-privilege rollouts',
      'Clear ownership of identity remediation tasks'
    ]
  },
  {
    slug: 'multi-cloud',
    navLabel: 'Multi-cloud',
    heroTitle: 'Solution for multi-cloud machine identity operations',
    description:
      'Unify fragmented identity posture and trust-path analysis across cloud and cluster boundaries with one operating model.',
    bullets: [
      'Normalize machine identity telemetry into one graph-backed workflow',
      'Apply consistent triage criteria across environments',
      'Track policy and exposure changes with centralized evidence'
    ],
    outcomes: [
      'Unified identity risk visibility across environments',
      'Lower operational overhead for security operations',
      'Improved governance consistency for compliance programs'
    ]
  },
  {
    slug: 'platform-engineering',
    navLabel: 'Platform Engineering',
    heroTitle: 'Solution for platform engineering organizations',
    description:
      'Ship authorization changes faster with simulation and staged rollout controls that protect production reliability.',
    bullets: [
      'Preview policy impact before enforcement',
      'Run controlled rollouts with rollback safety rails',
      'Share remediation context directly with service owners'
    ],
    outcomes: [
      'Faster delivery of least-privilege controls',
      'Lower risk of authorization-related outages',
      'Higher trust between security and platform teams'
    ]
  },
  {
    slug: 'security-teams',
    navLabel: 'Security Teams',
    heroTitle: 'Solution for security operations and detection teams',
    description:
      'Prioritize machine identity findings by exploitability and business impact, not by alert volume.',
    bullets: [
      'Surface high-signal findings tied to reachable critical assets',
      'Reduce queue noise with trust-path context and path scoring',
      'Route ownership quickly to teams that can execute remediation'
    ],
    outcomes: [
      'Lower mean time to remediation for identity findings',
      'Improved signal-to-noise in security queues',
      'Stronger executive reporting on identity risk reduction'
    ]
  }
] as const;

function upsertMetaByName(name: string, content: string) {
  let tag = document.querySelector(`meta[name="${name}"]`) as HTMLMetaElement | null;
  if (!tag) {
    tag = document.createElement('meta');
    tag.setAttribute('name', name);
    document.head.appendChild(tag);
  }
  tag.setAttribute('content', content);
}

function upsertMetaByProperty(property: string, content: string) {
  let tag = document.querySelector(`meta[property="${property}"]`) as HTMLMetaElement | null;
  if (!tag) {
    tag = document.createElement('meta');
    tag.setAttribute('property', property);
    document.head.appendChild(tag);
  }
  tag.setAttribute('content', content);
}

function upsertCanonical(path: string) {
  let link = document.querySelector('link[rel="canonical"]') as HTMLLinkElement | null;
  if (!link) {
    link = document.createElement('link');
    link.setAttribute('rel', 'canonical');
    document.head.appendChild(link);
  }
  link.setAttribute('href', `${SITE_URL}${path}`);
}

function upsertSchema(config: SeoConfig) {
  let tag = document.getElementById('identrail-schema') as HTMLScriptElement | null;
  if (!tag) {
    tag = document.createElement('script');
    tag.id = 'identrail-schema';
    tag.type = 'application/ld+json';
    document.head.appendChild(tag);
  }

  const schema = {
    '@context': 'https://schema.org',
    '@type': config.schemaType ?? 'WebPage',
    name: config.title,
    description: config.description,
    url: `${SITE_URL}${config.path}`,
    isPartOf: {
      '@type': 'WebSite',
      name: 'Identrail',
      url: SITE_URL,
      potentialAction: {
        '@type': 'SearchAction',
        target: `${SITE_URL}/blog?query={search_term_string}`,
        'query-input': 'required name=search_term_string'
      }
    },
    publisher: {
      '@type': 'Organization',
      name: 'Identrail',
      url: SITE_URL,
      sameAs: [GITHUB_REPO, DISCORD_URL]
    }
  };

  tag.textContent = JSON.stringify(schema);
}

function useSeo(config: SeoConfig) {
  useEffect(() => {
    document.title = config.title;
    upsertMetaByName('description', config.description);
    upsertMetaByName(
      'keywords',
      config.keywords ??
        'machine identity security, AWS IAM security, Kubernetes RBAC security, non-human identity management, trust graph security'
    );
    upsertMetaByProperty('og:title', config.title);
    upsertMetaByProperty('og:description', config.description);
    upsertMetaByProperty('og:type', 'website');
    upsertMetaByProperty('og:url', `${SITE_URL}${config.path}`);
    upsertMetaByProperty('og:image', `${SITE_URL}/identrail-logo.png`);
    upsertMetaByProperty('twitter:card', 'summary_large_image');
    upsertMetaByProperty('twitter:title', config.title);
    upsertMetaByProperty('twitter:description', config.description);
    upsertCanonical(config.path);
    upsertSchema(config);
  }, [config.title, config.description, config.path, config.keywords, config.schemaType]);
}

function useAnalytics() {
  const location = useLocation();

  useEffect(() => {
    const url = `${location.pathname}${location.search}${location.hash}`;

    if (window.gtag) {
      window.gtag('event', 'page_view', {
        page_path: url,
        page_title: document.title
      });
    }

    if (window.posthog) {
      window.posthog.capture('$pageview', {
        path: location.pathname,
        search: location.search,
        hash: location.hash
      });
    }
  }, [location]);
}

function useCtaVariant(experimentKey: string): string {
  const location = useLocation();
  const [variant, setVariant] = useState<'a' | 'b'>('a');

  useEffect(() => {
    const search = new URLSearchParams(location.search);
    const queryVariant = search.get('variant');
    const storageKey = `identrail-exp-${experimentKey}`;

    if (queryVariant === 'a' || queryVariant === 'b') {
      localStorage.setItem(storageKey, queryVariant);
      setVariant(queryVariant);
      window.identrailAB = { variant: queryVariant };
      return;
    }

    const persisted = localStorage.getItem(storageKey);
    if (persisted === 'a' || persisted === 'b') {
      setVariant(persisted);
      window.identrailAB = { variant: persisted };
      return;
    }

    const randomized: 'a' | 'b' = Math.random() > 0.5 ? 'a' : 'b';
    localStorage.setItem(storageKey, randomized);
    setVariant(randomized);
    window.identrailAB = { variant: randomized };
  }, [experimentKey, location.search]);

  return variant;
}

function SectionTitle({
  eyebrow,
  title,
  body
}: {
  eyebrow?: string;
  title: string;
  body?: string;
}) {
  return (
    <div className="idt-section-title">
      {eyebrow ? <p className="idt-eyebrow">{eyebrow}</p> : null}
      <h2>{title}</h2>
      {body ? <p>{body}</p> : null}
    </div>
  );
}

function LeadCaptureForm({
  title,
  caption,
  ctaLabel,
  compact = false
}: {
  title: string;
  caption: string;
  ctaLabel: string;
  compact?: boolean;
}) {
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitted(true);
  };

  return (
    <section className={`idt-lead-form ${compact ? 'is-compact' : ''}`} aria-label={title}>
      <h3>{title}</h3>
      <p>{caption}</p>

      {!submitted ? (
        <form onSubmit={handleSubmit} className="idt-form-grid">
          <label>
            Work email
            <input required type="email" name="email" autoComplete="email" placeholder="you@company.com" />
          </label>
          <label>
            Company
            <input required type="text" name="company" autoComplete="organization" placeholder="Acme Corp" />
          </label>
          <label>
            Biggest challenge
            <select name="challenge" defaultValue="Trust path visibility">
              <option>Trust path visibility</option>
              <option>Overprivileged service accounts</option>
              <option>Credential leak response</option>
              <option>Authorization rollout safety</option>
            </select>
          </label>
          <button type="submit" className="idt-btn idt-btn-primary">
            {ctaLabel}
          </button>
        </form>
      ) : (
        <p className="idt-form-success">Thanks. We will send a practical risk assessment framework within one business day.</p>
      )}
    </section>
  );
}

function ExitIntentPopup() {
  const [open, setOpen] = useState(false);
  const dismissedRef = useRef(false);

  useEffect(() => {
    const storageKey = 'identrail-exit-modal-dismissed';
    dismissedRef.current = localStorage.getItem(storageKey) === 'yes';

    if (dismissedRef.current) {
      return;
    }

    const onMouseOut = (event: MouseEvent) => {
      if (event.clientY <= 8 && !dismissedRef.current) {
        setOpen(true);
      }
    };

    const timer = window.setTimeout(() => {
      if (!dismissedRef.current) {
        setOpen(true);
      }
    }, 45000);

    document.addEventListener('mouseout', onMouseOut);

    return () => {
      window.clearTimeout(timer);
      document.removeEventListener('mouseout', onMouseOut);
    };
  }, []);

  const close = () => {
    dismissedRef.current = true;
    localStorage.setItem('identrail-exit-modal-dismissed', 'yes');
    setOpen(false);
  };

  if (!open) return null;

  return (
    <div className="idt-modal-backdrop" role="presentation" onClick={close}>
      <div className="idt-modal" role="dialog" aria-modal="true" aria-labelledby="exit-modal-title" onClick={(event) => event.stopPropagation()}>
        <button className="idt-modal-close" type="button" onClick={close} aria-label="Close">
          x
        </button>
        <h3 id="exit-modal-title">Before you leave: get your free machine identity risk assessment</h3>
        <p>
          Receive a practical checklist for AWS IAM, Kubernetes RBAC, and Git exposure risk.
        </p>
        <LeadCaptureForm
          compact
          title="Risk Assessment"
          caption="No spam. One actionable email with implementation steps."
          ctaLabel="Send Risk Checklist"
        />
      </div>
    </div>
  );
}

function CalendlyEmbed() {
  return (
    <section className="idt-calendly">
      <SectionTitle
        eyebrow="Book Demo"
        title="Walk through your trust graph in 15 minutes"
        body="Bring one AWS account or Kubernetes namespace, and we will map live trust paths and top risk chains."
      />
      <iframe
        title="Identrail demo booking"
        src={`${CALENDLY_URL}?hide_gdpr_banner=1`}
        loading="lazy"
        referrerPolicy="strict-origin-when-cross-origin"
      />
    </section>
  );
}

function TrustGraphHeroVisual() {
  return (
    <div className="idt-graph-visual" aria-hidden="true">
      <div className="idt-graph-grid" />
      <div className="idt-node idt-node-root">OIDC Provider</div>
      <div className="idt-node idt-node-role">AWS Role: payment-prod</div>
      <div className="idt-node idt-node-k8s">K8s SA: checkout-api</div>
      <div className="idt-node idt-node-repo">Git Repo: deploy-config</div>
      <span className="idt-edge idt-edge-a" />
      <span className="idt-edge idt-edge-b" />
      <span className="idt-edge idt-edge-c" />
      <span className="idt-pulse idt-pulse-a" />
      <span className="idt-pulse idt-pulse-b" />
    </div>
  );
}

function TrustGraphDemo() {
  const nodes = [
    {
      id: 'oidc',
      title: 'OIDC Provider',
      detail: 'Federated identity provider trusted by CI/CD and cluster workloads.'
    },
    {
      id: 'role',
      title: 'AWS Role: payments-prod',
      detail: 'Role assumed by automation workloads with cross-account permissions.'
    },
    {
      id: 'sa',
      title: 'K8s ServiceAccount: api-gateway',
      detail: 'Service account with namespace-level and cloud trust-path reachability.'
    },
    {
      id: 'repo',
      title: 'Git Repo: infra-live',
      detail: 'Repository contains deployment workflows and secrets exposure history.'
    },
    {
      id: 'db',
      title: 'RDS Resource: billing-ledger',
      detail: 'Sensitive resource reachable through chained assumptions in current policy state.'
    }
  ] as const;

  const [selectedId, setSelectedId] = useState<string>('role');
  const selected = nodes.find((item) => item.id === selectedId) ?? nodes[1];

  return (
    <section className="idt-demo-surface">
      <div className="idt-demo-graph" role="img" aria-label="Interactive trust graph simulation">
        {nodes.map((node) => (
          <button
            key={node.id}
            type="button"
            className={`idt-demo-node ${selected.id === node.id ? 'is-active' : ''}`}
            onClick={() => setSelectedId(node.id)}
          >
            <span>{node.title}</span>
          </button>
        ))}
        <span className="idt-demo-connector c1" />
        <span className="idt-demo-connector c2" />
        <span className="idt-demo-connector c3" />
        <span className="idt-demo-connector c4" />
      </div>
      <aside className="idt-demo-sidebar" aria-live="polite">
        <h3>{selected.title}</h3>
        <p>{selected.detail}</p>
        <ul>
          <li>Risk score impact: High</li>
          <li>Reachable resources: 18</li>
          <li>Recommended control: Staged trust policy tightening</li>
        </ul>
        <div className="idt-inline-actions">
          <Link to="/pricing" className="idt-btn idt-btn-primary">
            Try Free Hosted SaaS
          </Link>
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            Run Self-Hosted
          </SafeLink>
        </div>
      </aside>
    </section>
  );
}

type RoiNumberFieldProps = {
  id: string;
  label: string;
  value: number;
  min: number;
  step: number;
  onChange: (value: number) => void;
};

function RoiNumberField({ id, label, value, min, step, onChange }: RoiNumberFieldProps) {
  const updateValue = (next: number) => {
    const safe = Math.max(min, Math.round(next));
    onChange(safe);
  };

  return (
    <label htmlFor={id} className="idt-roi-field">
      <span>{label}</span>
      <div className="idt-roi-input-wrap">
        <input
          id={id}
          className="idt-roi-number-input"
          type="number"
          min={min}
          step={step}
          inputMode="numeric"
          value={value}
          onChange={(event) => {
            const parsed = Number(event.target.value);
            if (Number.isNaN(parsed)) {
              return;
            }
            updateValue(parsed);
          }}
        />
        <div className="idt-roi-stepper" role="group" aria-label={`${label} controls`}>
          <button type="button" onClick={() => updateValue(value - step)} aria-label={`Decrease ${label}`}>
            −
          </button>
          <button type="button" onClick={() => updateValue(value + step)} aria-label={`Increase ${label}`}>
            +
          </button>
        </div>
      </div>
    </label>
  );
}

function RoiCalculator() {
  const [identities, setIdentities] = useState(3200);
  const [incidentCost, setIncidentCost] = useState(195000);
  const [hoursPerWeek, setHoursPerWeek] = useState(44);

  const output = useMemo(() => {
    const annualHours = hoursPerWeek * 52;
    const laborSavings = annualHours * 110;
    const expectedIncidentReduction = incidentCost * 0.87;
    const identityRiskDelta = Math.round(identities * 0.32);

    return {
      laborSavings,
      expectedIncidentReduction,
      identityRiskDelta,
      estimatedTotal: laborSavings + expectedIncidentReduction
    };
  }, [hoursPerWeek, incidentCost, identities]);

  return (
    <section className="idt-roi" aria-label="ROI calculator">
      <SectionTitle
        eyebrow="ROI Calculator"
        title="See your potential risk and cost reduction"
        body="Estimate impact from reduced machine identity incidents and faster remediation workflows."
      />
      <div className="idt-roi-grid">
        <RoiNumberField
          id="roi-identities"
          label="Number of machine identities"
          value={identities}
          min={100}
          step={100}
          onChange={setIdentities}
        />
        <RoiNumberField
          id="roi-incident-cost"
          label="Average machine-identity incident cost (USD)"
          value={incidentCost}
          min={10000}
          step={5000}
          onChange={setIncidentCost}
        />
        <RoiNumberField
          id="roi-triage-hours"
          label="Weekly hours spent on identity triage"
          value={hoursPerWeek}
          min={1}
          step={1}
          onChange={setHoursPerWeek}
        />

        <div className="idt-roi-output" aria-live="polite">
          <p>
            Annual labor savings: <strong>${output.laborSavings.toLocaleString()}</strong>
          </p>
          <p>
            Reduced incident exposure: <strong>${output.expectedIncidentReduction.toLocaleString()}</strong>
          </p>
          <p>
            High-risk identities reduced: <strong>{output.identityRiskDelta.toLocaleString()}</strong>
          </p>
          <p className="idt-roi-total">
            Estimated annual impact: <strong>${output.estimatedTotal.toLocaleString()}</strong>
          </p>
        </div>
      </div>
    </section>
  );
}

function Header() {
  const [menuOpen, setMenuOpen] = useState(false);
  const ctaVariant = useCtaVariant('primary-cta-copy');
  const primaryCta = ctaVariant === 'b' ? 'Start Free Risk Scan' : 'Try Free Hosted SaaS';

  return (
    <header className="idt-header">
      <div className="idt-shell idt-header-row">
        <Link to="/" className="idt-brand" aria-label="Identrail homepage">
          <img src="/identrail-logo.png" width="32" height="32" alt="Identrail" />
          <span>
            Identrail
            <small>Machine Identity Security</small>
          </span>
        </Link>

        <button className="idt-menu-toggle" type="button" onClick={() => setMenuOpen((prev) => !prev)}>
          Menu
        </button>

        <nav className={`idt-nav ${menuOpen ? 'is-open' : ''}`} aria-label="Primary">
          {NAV_LINKS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => (isActive ? 'is-active' : '')}
              onClick={() => setMenuOpen(false)}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="idt-header-actions">
          <Link to="/pricing" className="idt-btn idt-btn-primary" data-ab-slot="header_primary_cta">
            {primaryCta}
          </Link>
          <Link to="/enterprise" className="idt-btn idt-btn-dark">
            Book Demo
          </Link>
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            GitHub
          </SafeLink>
        </div>
      </div>
    </header>
  );
}

function DeploymentPathBanner() {
  return (
    <section className="idt-section idt-shell idt-deployment-bridge" aria-label="Choose deployment">
      <div className="idt-deployment-panel">
        <p className="idt-eyebrow">Choose Deployment</p>
        <h2>Deploy open-source first, then scale to hosted or enterprise when you are ready.</h2>
        <p className="idt-deployment-copy">Open Source Self-Hosted • Hosted SaaS Pro • Enterprise Private Deployment</p>
        <div className="idt-inline-actions idt-inline-actions-tight">
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            Deploy OSS
          </SafeLink>
          <Link to="/pricing" className="idt-btn idt-btn-primary">
            Try Hosted SaaS
          </Link>
          <Link to="/enterprise" className="idt-btn idt-btn-dark">
            Talk to Sales
          </Link>
        </div>
      </div>
    </section>
  );
}

function GitHubIcon() {
  return (
    <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 2C6.48 2 2 6.59 2 12.25c0 4.52 2.87 8.35 6.84 9.7.5.1.68-.22.68-.49 0-.24-.01-.89-.01-1.75-2.78.62-3.37-1.37-3.37-1.37-.46-1.2-1.12-1.51-1.12-1.51-.92-.64.07-.63.07-.63 1.02.08 1.55 1.07 1.55 1.07.9 1.59 2.37 1.13 2.95.87.09-.67.35-1.13.64-1.39-2.22-.26-4.56-1.14-4.56-5.08 0-1.12.39-2.03 1.03-2.74-.1-.26-.45-1.31.1-2.73 0 0 .84-.27 2.75 1.05A9.4 9.4 0 0 1 12 6.8c.85 0 1.7.12 2.5.36 1.9-1.32 2.74-1.05 2.74-1.05.56 1.42.21 2.47.11 2.73.64.71 1.02 1.62 1.02 2.74 0 3.95-2.35 4.82-4.58 5.08.36.32.67.95.67 1.91 0 1.38-.01 2.49-.01 2.83 0 .27.18.6.69.49A10.25 10.25 0 0 0 22 12.25C22 6.59 17.52 2 12 2Z"
      />
    </svg>
  );
}

function LinkedInIcon() {
  return (
    <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
      <path
        fill="currentColor"
        d="M6.94 8.7A1.88 1.88 0 1 1 6.93 4.95 1.88 1.88 0 0 1 6.94 8.7Zm1.58 2.03v8.31H5.36v-8.3h3.16Zm4.95 0v1.13h.04c.44-.82 1.5-1.7 3.08-1.7 3.3 0 3.91 2.2 3.91 5.05v5.83h-3.16v-5.17c0-1.23-.02-2.8-1.68-2.8-1.68 0-1.94 1.33-1.94 2.71v5.26H10.56v-8.3h2.91Z"
      />
    </svg>
  );
}

function DiscordIcon() {
  return (
    <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
      <path
        fill="currentColor"
        d="M19.79 5.59A15.66 15.66 0 0 0 15.9 4.4l-.19.4a14.54 14.54 0 0 1 3.71 1.19 11.77 11.77 0 0 0-3.62-1.13c-2.39-.26-4.79-.26-7.18 0A11.7 11.7 0 0 0 5 6a14.56 14.56 0 0 1 3.71-1.19l-.19-.4a15.7 15.7 0 0 0-3.88 1.18C2.2 9.24 1.52 12.79 1.86 16.29a15.95 15.95 0 0 0 4.77 2.42l.95-1.58c-.52-.2-1.01-.45-1.49-.73.13.1.27.19.41.28 2.06 1.15 4.35 1.52 6.5 1.52 2.15 0 4.44-.37 6.49-1.52.14-.09.28-.18.41-.28-.47.28-.97.53-1.49.73l.95 1.58a15.92 15.92 0 0 0 4.77-2.42c.4-4.06-.68-7.58-2.53-10.7ZM9.54 14.14c-.76 0-1.39-.72-1.39-1.61s.61-1.6 1.39-1.6c.78 0 1.4.72 1.39 1.6 0 .9-.61 1.61-1.39 1.61Zm4.93 0c-.76 0-1.39-.72-1.39-1.61s.61-1.6 1.39-1.6c.78 0 1.4.72 1.39 1.6 0 .9-.61 1.61-1.39 1.61Z"
      />
    </svg>
  );
}

function XIcon() {
  return (
    <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
      <path
        fill="currentColor"
        d="m18.9 2 2.7 3.9-6.16 7.04L22 22h-5.2l-4.08-5.33L8.06 22H2.8l6.6-7.54L2 2h5.33l3.72 4.86L15.32 2H18.9Zm-1.82 17.04h1.48L6.48 4.84H4.9l12.18 14.2Z"
      />
    </svg>
  );
}

function Footer() {
  const footerLinks = [
    { to: '/solutions', label: 'Solutions' },
    { to: '/pricing', label: 'Pricing' },
    { to: '/demo', label: 'Demo' },
    { to: '/docs', label: 'Docs' },
    { to: '/blog', label: 'Blog' },
    { to: '/privacy', label: 'Privacy' },
    { to: '/terms', label: 'Terms' }
  ] as const;

  return (
    <footer className="idt-footer">
      <section className="idt-footer-showcase">
        <div className="idt-shell">
          <h2>Benefits</h2>
          <div className="idt-benefits-row">
            <span>Fast OSS Start</span>
            <span>Enterprise-Ready Controls</span>
            <span>Trust Graph Clarity</span>
            <span>Safer Rollouts</span>
          </div>
          <p>
            Start with the open-core platform, prove value quickly, and move to hosted or enterprise deployment without re-platforming.
          </p>
          <div className="idt-footer-cta-row">
            <Link to="/pricing" className="idt-footer-super-cta">
              <span>Start Free Risk Scan</span>
              <small>Try hosted SaaS or choose enterprise rollout</small>
            </Link>
          </div>
        </div>
      </section>

      <div className="idt-footer-bar">
        <div className="idt-shell idt-footer-bar-row">
          <nav className="idt-footer-links" aria-label="Footer">
            {footerLinks.map((item) => (
              <Link key={item.to} to={item.to}>
                {item.label}
              </Link>
            ))}
          </nav>
          <small>© {new Date().getFullYear()} Identrail. All rights reserved.</small>
          <div className="idt-footer-socials">
            <SafeLink href={X_URL} aria-label="X" className="idt-social-link">
              <XIcon />
            </SafeLink>
            <SafeLink href={LINKEDIN_URL} aria-label="LinkedIn" className="idt-social-link">
              <LinkedInIcon />
            </SafeLink>
            <SafeLink href={GITHUB_REPO} aria-label="GitHub" className="idt-social-link">
              <GitHubIcon />
            </SafeLink>
            <SafeLink href={DISCORD_URL} aria-label="Discord" className="idt-social-link">
              <DiscordIcon />
            </SafeLink>
          </div>
        </div>
      </div>
    </footer>
  );
}

function HomePage() {
  const seo: SeoConfig = {
    title: 'Identrail | Machine Identities, Fully Visible. Risks, Fully Controlled.',
    description:
      'Open-core machine identity security for AWS IAM, Kubernetes RBAC, and Git repositories. Discover trust paths, cut blast radius, and deploy safer authorization controls.',
    path: '/',
    schemaType: 'WebPage'
  };
  useSeo(seo);

  const ctaVariant = useCtaVariant('home-hero-primary');

  return (
    <>
      <section className="idt-hero">
        <div className="idt-shell idt-hero-grid">
          <div>
            <p className="idt-eyebrow">Open-Core Machine Identity Security</p>
            <h1>Machine Identities, Fully Visible. Risks, Fully Controlled.</h1>
            <p className="idt-lead">
              Discover every IAM role, Kubernetes service account, and trust path. Reduce blast radius by 87% in minutes with open-source core and enterprise SaaS.
            </p>
            <div className="idt-inline-actions" data-ab-slot="hero_primary_cta">
              <Link to="/pricing" className="idt-btn idt-btn-primary">
                {ctaVariant === 'b' ? 'Start Free Risk Scan' : 'Try Free Hosted SaaS'}
              </Link>
              <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
                Star on GitHub
              </SafeLink>
              <Link to="/enterprise" className="idt-btn idt-btn-dark">
                Book 15-min Demo
              </Link>
            </div>
            <div className="idt-kpi-row">
              <article>
                <strong>87%</strong>
                <span>Average high-risk trust path reduction</span>
              </article>
              <article>
                <strong>&lt; 15 min</strong>
                <span>Time to first trust graph in hosted SaaS</span>
              </article>
              <article>
                <strong>3x faster</strong>
                <span>Identity triage workflows for security teams</span>
              </article>
            </div>
          </div>
          <TrustGraphHeroVisual />
        </div>
      </section>

      <section className="idt-trust-strip" aria-label="Trusted by platform teams">
        <div className="idt-shell">
          <p>Trusted by platform teams at modern cloud-native organizations</p>
          <div className="idt-logo-row">
            {TRUSTED_LOGOS.map((logo) => (
              <span key={logo}>{logo}</span>
            ))}
          </div>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Problem to Solution"
          title="Machine identity complexity grows faster than most security programs"
          body="Identrail turns fragmented IAM and RBAC data into a prioritized graph of exposures and remediation paths."
        />
        <div className="idt-card-grid three-col">
          <article className="idt-card">
            <h3>Fragmented visibility</h3>
            <p>Cloud IAM, Kubernetes RBAC, and repository signals live in different systems with no unified risk context.</p>
          </article>
          <article className="idt-card">
            <h3>Blast radius uncertainty</h3>
            <p>Security teams struggle to answer who can actually reach crown-jewel resources through trust chains.</p>
          </article>
          <article className="idt-card">
            <h3>Risky policy rollouts</h3>
            <p>Least privilege initiatives stall when policy changes can break production workloads.</p>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Interactive Preview"
          title="Trust Graph teaser"
          body="Explore one machine trust path and see why this feature is central to triage and remediation velocity."
        />
        <TrustGraphDemo />
      </section>

      <section className="idt-section idt-shell">
        <SectionTitle eyebrow="How It Works" title="From data collection to safe control in four steps" />
        <ol className="idt-steps">
          <li>
            <h3>1. Connect data sources</h3>
            <p>Ingest AWS IAM, Kubernetes identities, and repository signals continuously.</p>
          </li>
          <li>
            <h3>2. Build trust paths</h3>
            <p>Correlate principals, permissions, resources, and transitive assumptions in one graph.</p>
          </li>
          <li>
            <h3>3. Detect high-signal exposures</h3>
            <p>Prioritize findings based on exploitability, sensitivity, and path reachability.</p>
          </li>
          <li>
            <h3>4. Roll out safer controls</h3>
            <p>Simulate policy updates, stage changes, and ship with kill-switch safety rails.</p>
          </li>
        </ol>
      </section>

      <DeploymentPathBanner />

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Open-Core Advantage"
          title="Purpose-built alternative to closed machine identity platforms"
          body="Identrail combines transparency, speed, and enterprise control without vendor lock-in."
        />
        <div className="idt-table-wrap">
          <table className="idt-compare-table">
            <thead>
              <tr>
                <th scope="col">Category</th>
                <th scope="col">Identrail</th>
                <th scope="col">Typical closed alternatives</th>
              </tr>
            </thead>
            <tbody>
              {DIFFERENTIATION_ROWS.map((row) => (
                <tr key={row.area}>
                  <th scope="row">{row.area}</th>
                  <td>{row.identrail}</td>
                  <td>{row.alternatives}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Customer Signals"
          title="Teams improving machine identity posture with measurable outcomes"
          body="Security and platform organizations use Identrail to cut time-to-remediation and reduce incident exposure."
        />
        <div className="idt-quote-row" role="list">
          {SOCIAL_QUOTES.map((quote) => (
            <article key={quote.quote} className="idt-quote-card" role="listitem">
              <p>{quote.quote}</p>
              <strong>{quote.name}</strong>
              <span>{quote.company}</span>
            </article>
          ))}
        </div>
      </section>

      <section className="idt-section idt-shell">
        <RoiCalculator />
      </section>

      <section className="idt-section idt-shell idt-final-cta">
        <SectionTitle
          eyebrow="Get Started"
          title="Run Identrail your way: hosted SaaS, self-hosted OSS, or enterprise"
          body="Choose the adoption path that matches your security and platform maturity today."
        />
        <div className="idt-inline-actions">
          <Link to="/pricing" className="idt-btn idt-btn-primary">
            Try Free Hosted SaaS
          </Link>
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            Self-Host from GitHub
          </SafeLink>
          <Link to="/enterprise" className="idt-btn idt-btn-dark">
            Talk to Sales
          </Link>
        </div>
        <LeadCaptureForm
          title="Get Free Risk Assessment"
          caption="Tell us your machine identity goals and we will send a practical 30-day plan."
          ctaLabel="Get Free Risk Assessment"
        />
      </section>
    </>
  );
}

function ProductPage() {
  useSeo({
    title: 'Product | Identrail Machine Identity Security Platform',
    description:
      'Discover machine identities across AWS and Kubernetes, map trust paths, detect risk, and enforce safer authorization controls with Identrail.',
    path: '/product',
    schemaType: 'Product'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Product</p>
        <h1>One platform for machine identity visibility, detection, and control</h1>
        <p>
          Identrail unifies IAM graph discovery, repository exposure scanning, and rollout-safe authorization workflows into one operator-grade platform.
        </p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          <article className="idt-card">
            <h2>Trust Graph Explorer</h2>
            <p>Interactive mapping of principals, assumptions, actions, and reachable resources across cloud and Kubernetes.</p>
            <ul>
              <li>Trace blast radius from any machine identity</li>
              <li>Explain each trust edge with source policy evidence</li>
              <li>Compare current and proposed policy states</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Detection and Triage Engine</h2>
            <p>High-signal detections for overprivileged paths, stale credentials, and risky identity chains.</p>
            <ul>
              <li>Risk scoring with business context</li>
              <li>Actionable remediation guidance</li>
              <li>Ticket and workflow integrations</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Repo Exposure Scanner</h2>
            <p>Continuously scan source repositories and CI artifacts for leaked credentials and unsafe patterns.</p>
            <ul>
              <li>Built-in and custom detectors</li>
              <li>Git-aware triage with finding history</li>
              <li>Correlates secret leaks to trust paths</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Rollout-Safe Authorization Controls</h2>
            <p>Enforce least privilege with policy simulation, staged rollout, and fast rollback safety rails.</p>
            <ul>
              <li>Policy impact simulation before deploy</li>
              <li>Progressive rollout controls</li>
              <li>Kill switch and audit trail support</li>
            </ul>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Hero Feature"
          title="The Trust Graph: your control plane for machine identity risk"
          body="Investigate every risky path from source identity to sensitive resource with explainable graph evidence."
        />
        <TrustGraphDemo />
      </section>

      <section className="idt-section idt-shell">
        <LeadCaptureForm
          title="Want a technical walkthrough?"
          caption="Book a product session with platform architects and security engineers."
          ctaLabel="Book Technical Demo"
        />
      </section>
    </>
  );
}

function FeaturesPage() {
  useSeo({
    title: 'Features | AWS IAM, Kubernetes RBAC, Git Scanner, Trust Graph',
    description:
      'Explore Identrail features for AWS machine identities, Kubernetes RBAC visibility, Git exposure scanning, and interactive trust graph analysis.',
    path: '/features'
  });

  const featureSummaries = [
    {
      id: 'aws',
      title: 'AWS IAM Security',
      body: 'Discover roles, policies, trust relationships, and cross-account assumptions in one explainable graph.',
      href: '/features/aws',
      bullets: [
        'Map role assumption chains and transitive trust paths',
        'Detect wildcard trust and overprivileged action sets',
        'Prioritize exposure by reachable resource sensitivity'
      ]
    },
    {
      id: 'kubernetes',
      title: 'Kubernetes Machine Identity',
      body: 'Correlate service accounts, tokens, RBAC bindings, and workload privileges with cluster context.',
      href: '/features/kubernetes',
      bullets: [
        'Identify namespace and cluster-level privilege escalation paths',
        'Trace service account to cloud-role federation',
        'Simulate RBAC control tightening before rollout'
      ]
    },
    {
      id: 'git-scanner',
      title: 'Git Scanner',
      body: 'Scan repositories for machine credential leaks and risky identity configuration patterns.',
      href: '/features/git-scanner',
      bullets: [
        'Continuous and historical scan support',
        'Policy-backed detector tuning',
        'Findings linked directly to trust graph context'
      ]
    },
    {
      id: 'trust-graph',
      title: 'Interactive Trust Graph',
      body: 'Visualize how identities reach resources and why a detection matters, with actionable remediation paths.',
      href: '/features/trust-graph',
      bullets: [
        'Path-based impact previews',
        'Evidence snapshots for audits',
        'Exportable remediation stories for engineering teams'
      ]
    }
  ] as const;

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Features</p>
        <h1>Built for cloud-native machine identity security at scale</h1>
        <p>Deep technical workflows for security and platform teams, from discovery to rollout-safe control.</p>
      </section>

      {featureSummaries.map((feature) => (
        <section key={feature.id} className="idt-section idt-shell" id={feature.id}>
          <article className="idt-card idt-feature-callout">
            <h2>{feature.title}</h2>
            <p>{feature.body}</p>
            <ul>
              {feature.bullets.map((bullet) => (
                <li key={bullet}>{bullet}</li>
              ))}
            </ul>
            <div className="idt-inline-actions idt-inline-actions-tight">
              <Link to={feature.href} className="idt-btn idt-btn-primary">
                Explore {feature.title}
              </Link>
              <Link to="/demo" className="idt-btn idt-btn-ghost">
                Open Demo
              </Link>
            </div>
          </article>
        </section>
      ))}
    </>
  );
}

function FeatureDetailPage({ page }: { page: (typeof FEATURE_DEEP_PAGES)[number] }) {
  useSeo({
    title: `${page.heroTitle} | Identrail Features`,
    description: page.description,
    path: `/features/${page.slug}`
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Feature: {page.navLabel}</p>
        <h1>{page.heroTitle}</h1>
        <p>{page.description}</p>
        <div className="idt-inline-actions">
          <Link to="/demo" className="idt-btn idt-btn-primary">
            Open Interactive Demo
          </Link>
          <Link to="/pricing" className="idt-btn idt-btn-dark">
            Try Free Hosted SaaS
          </Link>
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            Star on GitHub
          </SafeLink>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          <article className="idt-card">
            <h2>What this feature gives you</h2>
            <ul>
              {page.bullets.map((bullet) => (
                <li key={bullet}>{bullet}</li>
              ))}
            </ul>
          </article>
          <article className="idt-card">
            <h2>Expected outcomes</h2>
            <ul>
              {page.outcomes.map((outcome) => (
                <li key={outcome}>{outcome}</li>
              ))}
            </ul>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <LeadCaptureForm
          title={`Get a ${page.navLabel} workflow walkthrough`}
          caption="Share your environment goals and we will tailor a practical machine identity rollout plan."
          ctaLabel="Get Free Risk Assessment"
        />
      </section>
    </>
  );
}

function SolutionsPage() {
  useSeo({
    title: 'Solutions | AWS, Kubernetes, Multi-cloud, Security and Platform Teams',
    description:
      'Solution patterns for AWS IAM, Kubernetes RBAC, multi-cloud identities, platform engineering teams, and security operations.',
    path: '/solutions'
  });

  const solutions = [
    {
      title: 'AWS Security Teams',
      body: 'Reduce IAM blast radius with trust path evidence, role chain analysis, and policy simulations.',
      metric: 'Cut overprivileged role exposure by 60-90%',
      href: '/solutions/aws'
    },
    {
      title: 'Kubernetes Platform Teams',
      body: 'Gain visibility into service account privileges and prevent RBAC drift before incidents happen.',
      metric: 'Reduce cluster authz incidents with staged controls',
      href: '/solutions/kubernetes'
    },
    {
      title: 'Multi-cloud Environments',
      body: 'Normalize machine identity data across providers with one operational control layer.',
      metric: 'Unify remediation workflows across clouds',
      href: '/solutions/multi-cloud'
    },
    {
      title: 'Platform Engineering',
      body: 'Ship authorization changes faster with simulation, rollout safety, and clear policy traceability.',
      metric: 'Deliver identity controls without release friction',
      href: '/solutions/platform-engineering'
    },
    {
      title: 'Security Operations',
      body: 'Prioritize detections with high exploitability and route to owners using trust graph context.',
      metric: 'Lower mean time to remediation',
      href: '/solutions/security-teams'
    }
  ] as const;

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Solutions</p>
        <h1>Deployment-ready outcomes for every team responsible for machine identity risk</h1>
      </section>
      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          {solutions.map((solution) => (
            <article key={solution.title} className="idt-card">
              <h2>{solution.title}</h2>
              <p>{solution.body}</p>
              <p className="idt-muted-strong">{solution.metric}</p>
              <div className="idt-inline-actions idt-inline-actions-tight">
                <Link to={solution.href} className="idt-btn idt-btn-primary">
                  Explore solution
                </Link>
              </div>
            </article>
          ))}
        </div>
      </section>
      <section className="idt-section idt-shell">
        <CalendlyEmbed />
      </section>
    </>
  );
}

function SolutionDetailPage({ page }: { page: (typeof SOLUTION_DEEP_PAGES)[number] }) {
  useSeo({
    title: `${page.heroTitle} | Identrail Solutions`,
    description: page.description,
    path: `/solutions/${page.slug}`
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Solution: {page.navLabel}</p>
        <h1>{page.heroTitle}</h1>
        <p>{page.description}</p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          <article className="idt-card">
            <h2>How teams use this solution</h2>
            <ul>
              {page.bullets.map((bullet) => (
                <li key={bullet}>{bullet}</li>
              ))}
            </ul>
          </article>
          <article className="idt-card">
            <h2>Business outcomes</h2>
            <ul>
              {page.outcomes.map((outcome) => (
                <li key={outcome}>{outcome}</li>
              ))}
            </ul>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-inline-actions">
          <Link to="/enterprise" className="idt-btn idt-btn-primary">
            Book 15-min Demo
          </Link>
          <Link to="/pricing" className="idt-btn idt-btn-dark">
            Compare Plans
          </Link>
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            Deploy Self-Hosted
          </SafeLink>
        </div>
      </section>
    </>
  );
}

function PricingPage() {
  useSeo({
    title: 'Pricing | Open Source, Pro SaaS, and Enterprise',
    description:
      'Compare Identrail pricing plans: open source self-hosted, Pro hosted SaaS, and Enterprise machine identity security.',
    path: '/pricing',
    schemaType: 'Product'
  });

  const [annual, setAnnual] = useState(true);
  const [salesModalOpen, setSalesModalOpen] = useState(false);

  const proPrice = annual ? 59 : 79;

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Pricing</p>
        <h1>Choose your rollout path: open source, hosted Pro, or enterprise scale</h1>
        <p>Start free and move up as your machine identity program matures.</p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-pricing-toggle" role="group" aria-label="Pricing cadence">
          <button type="button" className={!annual ? 'is-active' : ''} onClick={() => setAnnual(false)}>
            Monthly
          </button>
          <button type="button" className={annual ? 'is-active' : ''} onClick={() => setAnnual(true)}>
            Annual <span>Save 25%</span>
          </button>
        </div>

        <div className="idt-pricing-grid">
          <article className="idt-pricing-card">
            <h2>Open Source</h2>
            <p className="idt-price">$0</p>
            <p>Self-hosted core platform for AWS + Kubernetes machine identity workflows.</p>
            <ul>
              <li>Trust graph + exposure detections</li>
              <li>Community support</li>
              <li>API and docs access</li>
            </ul>
            <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
              Deploy Self-Hosted
            </SafeLink>
          </article>

          <article className="idt-pricing-card is-featured">
            <p className="idt-badge">Most Popular</p>
            <h2>Pro</h2>
            <p className="idt-price">
              ${proPrice}
              <span>/user/mo</span>
            </p>
            <p>Hosted SaaS with advanced detections, collaboration workflows, and managed operations.</p>
            <ul>
              <li>Everything in Open Source</li>
              <li>Hosted trust graph and accelerated queries</li>
              <li>SAML SSO, alerts, and workflow integrations</li>
            </ul>
            <Link to="/enterprise" className="idt-btn idt-btn-primary">
              Try Free Hosted SaaS
            </Link>
          </article>

          <article className="idt-pricing-card">
            <h2>Enterprise</h2>
            <p className="idt-price">Starting at $50k/yr</p>
            <p>Advanced governance, private deployment options, and enterprise-grade support.</p>
            <ul>
              <li>Everything in Pro</li>
              <li>SCIM, regional controls, and private tenancy</li>
              <li>24/7 support, SLA, TAM, and onboarding program</li>
            </ul>
            <button type="button" className="idt-btn idt-btn-dark" onClick={() => setSalesModalOpen(true)}>
              Contact Sales
            </button>
          </article>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <SectionTitle
          eyebrow="Feature Matrix"
          title="Compare plan capabilities"
          body="Move from OSS to enterprise without replacing your workflows."
        />
        <div className="idt-table-wrap">
          <table className="idt-compare-table">
            <thead>
              <tr>
                <th scope="col">Capability</th>
                <th scope="col">Open Source</th>
                <th scope="col">Pro</th>
                <th scope="col">Enterprise</th>
              </tr>
            </thead>
            <tbody>
              {FEATURE_ROWS.map((row) => (
                <tr key={row.capability}>
                  <th scope="row">{row.capability}</th>
                  <td>{row.openSource}</td>
                  <td>{row.pro}</td>
                  <td>{row.enterprise}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="idt-section idt-shell">
        <RoiCalculator />
      </section>

      {salesModalOpen ? (
        <div className="idt-modal-backdrop" onClick={() => setSalesModalOpen(false)} role="presentation">
          <div className="idt-modal" role="dialog" aria-modal="true" aria-labelledby="sales-modal-title" onClick={(event) => event.stopPropagation()}>
            <button
              type="button"
              className="idt-modal-close"
              aria-label="Close"
              onClick={() => setSalesModalOpen(false)}
            >
              x
            </button>
            <h3 id="sales-modal-title">Contact Enterprise Sales</h3>
            <p>Tell us your environment size and compliance goals. We will tailor a deployment and pricing plan.</p>
            <LeadCaptureForm
              compact
              title="Enterprise Sales"
              caption="Expected response time: under 1 business day."
              ctaLabel="Request Enterprise Proposal"
            />
          </div>
        </div>
      ) : null}
    </>
  );
}

function DemoPage() {
  useSeo({
    title: 'Demo | Interactive Trust Graph',
    description:
      'Explore the Identrail interactive trust graph demo for AWS IAM and Kubernetes machine identities.',
    path: '/demo'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Interactive Demo</p>
        <h1>Simulate real trust-path investigation in a production-style environment</h1>
        <p>Explore node relationships, inspect risk context, and test rollout-safe controls from one console.</p>
      </section>

      <section className="idt-section idt-shell">
        <TrustGraphDemo />
      </section>

      <section className="idt-section idt-shell idt-connect-cloud">
        <SectionTitle
          eyebrow="Next Step"
          title="One-click connect your cloud"
          body="Start in hosted SaaS or self-host OSS and import your first AWS account or Kubernetes cluster."
        />
        <div className="idt-inline-actions">
          <Link to="/pricing" className="idt-btn idt-btn-primary">
            Try Free Hosted SaaS
          </Link>
          <SafeLink href={GITHUB_REPO} className="idt-btn idt-btn-ghost">
            Run Self-Hosted
          </SafeLink>
        </div>
      </section>
    </>
  );
}

function DocsPage() {
  useSeo({
    title: 'Docs | Identrail Documentation',
    description:
      'Developer-first machine identity documentation with quickstarts, architecture, deployment runbooks, and API guides.',
    path: '/docs'
  });

  const [query, setQuery] = useState('');
  const normalized = query.trim().toLowerCase();

  const filtered = DOC_ENTRIES.filter((entry) => {
    if (!normalized) return true;
    return (
      entry.title.toLowerCase().includes(normalized) ||
      entry.description.toLowerCase().includes(normalized) ||
      entry.tags.some((tag) => tag.toLowerCase().includes(normalized))
    );
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Docs</p>
        <h1>Beautiful docs experience with deep operator workflows</h1>
        <p>Mintlify-style navigation, fast search, and practical runbooks linked to the source repository.</p>
        <SafeLink href={DOCS_REPO} className="idt-btn idt-btn-primary">
          Open Full GitHub Docs
        </SafeLink>
      </section>

      <section className="idt-section idt-shell">
        <label className="idt-search" htmlFor="docs-query">
          Search docs topics
          <input
            id="docs-query"
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Try: kubernetes, hardening, quickstart"
          />
        </label>

        <div className="idt-card-grid two-col">
          {filtered.map((entry) => (
            <article key={entry.href} className="idt-card">
              <h2>{entry.title}</h2>
              <p>{entry.description}</p>
              <p className="idt-doc-tags">{entry.tags.join(' / ')}</p>
              <SafeLink href={entry.href} className="idt-btn idt-btn-ghost">
                Read guide
              </SafeLink>
            </article>
          ))}
        </div>
      </section>

      <section className="idt-section idt-shell">
        <CalendlyEmbed />
      </section>
    </>
  );
}

function BlogPage() {
  useSeo({
    title: 'Blog & Resources | Machine Identity Security Insights',
    description:
      'SEO-optimized resources on machine identity security, Kubernetes machine identity, AWS NHI security, and non-human identity management.',
    path: '/blog',
    schemaType: 'Article'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Blog & Resources</p>
        <h1>Actionable content for security and platform teams operating machine identities</h1>
        <p>Educational deep dives, implementation playbooks, and strategic guidance for enterprise buyers.</p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          {BLOG_POSTS.map((post) => (
            <article key={post.slug} className="idt-card">
              <p className="idt-chip-row">
                <span>{post.category}</span>
                <span>{post.readTime}</span>
              </p>
              <h2>{post.title}</h2>
              <p>{post.description}</p>
              <p className="idt-muted-strong">Meta description ready for SEO snippets.</p>
              <Link to="/enterprise" className="idt-btn idt-btn-ghost">
                Request this guide
              </Link>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}

function SecurityPage() {
  useSeo({
    title: 'Security & Compliance | Identrail',
    description:
      'Security, compliance, and trust information for Identrail including SOC 2 roadmap, ISO 27001 controls, bug bounty, and data residency.',
    path: '/security'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Security & Compliance</p>
        <h1>Security-first architecture with transparent compliance posture</h1>
        <p>Built for teams that need hardening depth, audit evidence, and enterprise trust controls.</p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          <article className="idt-card">
            <h2>Compliance roadmap</h2>
            <ul>
              <li>SOC 2 Type II: In progress, target completion Q4 2026</li>
              <li>ISO 27001: Control framework in implementation</li>
              <li>Customer security questionnaires: Supported</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Security program</h2>
            <ul>
              <li>Vulnerability disclosure via security.txt</li>
              <li>Third-party penetration testing summary available under NDA</li>
              <li>Secure SDLC with code scanning and dependency management</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Data residency</h2>
            <ul>
              <li>Hosted SaaS regions: US and EU</li>
              <li>Enterprise private tenancy options</li>
              <li>Self-hosted deployment for full data control</li>
            </ul>
          </article>
          <article className="idt-card">
            <h2>Trust center operations</h2>
            <ul>
              <li>Documented incident response runbook</li>
              <li>Encryption in transit and at rest</li>
              <li>Role-based access and least-privilege internal controls</li>
            </ul>
          </article>
        </div>
      </section>
      <section className="idt-section idt-shell">
        <LeadCaptureForm
          title="Need vendor security documentation?"
          caption="Request security package access for procurement and compliance review."
          ctaLabel="Request Security Package"
        />
      </section>
    </>
  );
}

function AboutPage() {
  useSeo({
    title: 'About Identrail | Open-Core Machine Identity Company',
    description:
      'Learn about Identrail, the open-core machine identity security platform built for AWS, Kubernetes, and modern platform teams.',
    path: '/about',
    schemaType: 'AboutPage'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Company</p>
        <h1>Building the future control plane for machine identity security</h1>
        <p>
          Identrail exists to make machine identity risk understandable, operable, and controllable for every engineering-driven organization.
        </p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          <article className="idt-card">
            <h2>Mission</h2>
            <p>Help teams discover and control non-human identity risk before it becomes incident-level blast radius.</p>
          </article>
          <article className="idt-card">
            <h2>Model</h2>
            <p>Open-source core for speed and transparency, plus hosted and enterprise options for scale.</p>
          </article>
          <article className="idt-card">
            <h2>Community</h2>
            <p>Developer-first collaboration through GitHub, docs, contributor guides, and Discord.</p>
          </article>
          <article className="idt-card">
            <h2>Enterprise partnership</h2>
            <p>Support for procurement, compliance, and strategic deployment in regulated environments.</p>
          </article>
        </div>
      </section>
    </>
  );
}

function EnterprisePage() {
  useSeo({
    title: 'Enterprise Sales | Identrail',
    description:
      'Talk to Identrail enterprise sales for machine identity security programs spanning AWS, Kubernetes, and software supply chain risk.',
    path: '/enterprise'
  });

  return (
    <>
      <section className="idt-page-hero idt-shell">
        <p className="idt-eyebrow">Enterprise</p>
        <h1>Enterprise machine identity programs that satisfy security, platform, and procurement stakeholders</h1>
        <p>
          Standard deal range: $50k-$500k+ ACV with tailored rollout plans, architecture support, and compliance alignment.
        </p>
      </section>

      <section className="idt-section idt-shell">
        <div className="idt-card-grid two-col">
          <article className="idt-card">
            <h2>What enterprise buyers get</h2>
            <ul>
              <li>Private tenancy and data residency options</li>
              <li>SSO/SAML, SCIM, and granular access controls</li>
              <li>24/7 support with named technical account manager</li>
              <li>Joint rollout plan for high-impact environments</li>
            </ul>
          </article>
          <LeadCaptureForm
            title="Talk to Enterprise Sales"
            caption="Share environment scope and business goals to get a deployment blueprint and pricing proposal."
            ctaLabel="Request Enterprise Demo"
          />
        </div>
      </section>

      <section className="idt-section idt-shell">
        <CalendlyEmbed />
      </section>
    </>
  );
}

function LegalPage({ title, body }: { title: string; body: string }) {
  useSeo({
    title: `${title} | Identrail`,
    description: `${title} policy for Identrail website and platform experiences.`,
    path: `/${title.toLowerCase().replace(/\s+/g, '-')}`
  });

  return (
    <section className="idt-page-hero idt-shell">
      <h1>{title}</h1>
      <p>{body}</p>
    </section>
  );
}

function NotFoundPage() {
  useSeo({
    title: 'Page Not Found | Identrail',
    description: 'The page you requested could not be found.',
    path: '/404'
  });

  return (
    <section className="idt-page-hero idt-shell">
      <h1>404: Page not found</h1>
      <p>The page may have moved. Use the links below to continue.</p>
      <div className="idt-inline-actions">
        <Link to="/" className="idt-btn idt-btn-primary">
          Go to Homepage
        </Link>
        <Link to="/docs" className="idt-btn idt-btn-ghost">
          Open Docs
        </Link>
      </div>
    </section>
  );
}

function RoutedSite() {
  useAnalytics();

  return (
    <div className="idt-site">
      <a className="idt-skip" href="#main-content">
        Skip to content
      </a>

      <Header />

      <main id="main-content">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/product" element={<ProductPage />} />
          <Route path="/features" element={<FeaturesPage />} />
          <Route path="/features/aws" element={<FeatureDetailPage page={FEATURE_DEEP_PAGES[0]} />} />
          <Route path="/features/kubernetes" element={<FeatureDetailPage page={FEATURE_DEEP_PAGES[1]} />} />
          <Route path="/features/git-scanner" element={<FeatureDetailPage page={FEATURE_DEEP_PAGES[2]} />} />
          <Route path="/features/trust-graph" element={<FeatureDetailPage page={FEATURE_DEEP_PAGES[3]} />} />
          <Route path="/solutions" element={<SolutionsPage />} />
          <Route path="/solutions/aws" element={<SolutionDetailPage page={SOLUTION_DEEP_PAGES[0]} />} />
          <Route path="/solutions/kubernetes" element={<SolutionDetailPage page={SOLUTION_DEEP_PAGES[1]} />} />
          <Route path="/solutions/multi-cloud" element={<SolutionDetailPage page={SOLUTION_DEEP_PAGES[2]} />} />
          <Route path="/solutions/platform-engineering" element={<SolutionDetailPage page={SOLUTION_DEEP_PAGES[3]} />} />
          <Route path="/solutions/security-teams" element={<SolutionDetailPage page={SOLUTION_DEEP_PAGES[4]} />} />
          <Route path="/pricing" element={<PricingPage />} />
          <Route path="/demo" element={<DemoPage />} />
          <Route path="/docs" element={<DocsPage />} />
          <Route path="/blog" element={<BlogPage />} />
          <Route path="/security" element={<SecurityPage />} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="/enterprise" element={<EnterprisePage />} />
          <Route path="/terms" element={<LegalPage title="Terms" body="Use of this website and platform is subject to our terms and acceptable use obligations." />} />
          <Route path="/privacy" element={<LegalPage title="Privacy" body="We handle personal data responsibly and provide transparent controls for privacy and communication preferences." />} />
          <Route path="/privacy-choices" element={<LegalPage title="Privacy Choices" body="Manage analytics, communications, and data usage preferences for Identrail web experiences." />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>

      <Footer />
      <ExitIntentPopup />
    </div>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <RoutedSite />
    </BrowserRouter>
  );
}
