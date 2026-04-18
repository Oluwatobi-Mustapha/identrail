import { useMemo, useState } from 'react';
import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const modules = [
  { title: 'Reachable Trust Path', body: 'Trace how a machine identity can move across roles, service accounts, and policies.', href: siteLinks.technicalDocs },
  { title: 'Findings Queue', body: 'Prioritized risks with blast-radius context and practical remediation guidance.', href: siteLinks.findingsDocs },
  { title: 'Policy Simulation', body: 'Preview policy impact before rollout to prevent authorization regressions.', href: siteLinks.policyDocs },
  { title: 'Repo Scanner', body: 'Catch leaked secrets and trust misconfigurations directly in source repositories.', href: siteLinks.repoScannerDocs }
] as const;

const awsNodes = ['OIDC Provider', 'CI Role', 'Build Role', 'Prod Role', 'S3 Assets'];
const k8sNodes = ['Cluster SA', 'Namespace SA', 'Workload Pod', 'Vault Secret', 'KMS Key'];

export function TechnicalShowcaseSection() {
  const [view, setView] = useState<'aws' | 'k8s'>('aws');
  const [activeNode, setActiveNode] = useState(0);

  const nodes = view === 'aws' ? awsNodes : k8sNodes;
  const signal = useMemo(() => {
    const current = nodes[activeNode] ?? nodes[0];
    return view === 'aws'
      ? `Potential path: ${current} → Prod Role with elevated assume permission.`
      : `Potential path: ${current} → Vault Secret via over-broad service account trust.`;
  }, [activeNode, nodes, view]);

  return (
    <section className="mk-section" aria-labelledby="mk-tech-title">
      <div className="mk-shell">
        <div className="mk-section-head">
          <p className="mk-eyebrow">Technical Depth</p>
          <h2 id="mk-tech-title">Real security workflows, not just dashboards</h2>
        </div>

        <div className="mk-tech-grid">
          <div className="mk-tech-cards">
            {modules.map((module) => (
              <article key={module.title}>
                <h3>{module.title}</h3>
                <p>{module.body}</p>
                <SafeLink href={module.href}>View details</SafeLink>
              </article>
            ))}
          </div>

          <article className="mk-demo">
            <header>
              <h3>Try the Identrail Trust Graph</h3>
              <p>Switch environments and inspect simulated risk paths.</p>
            </header>

            <div className="mk-toggle" role="tablist" aria-label="Cloud environment toggle">
              <button
                type="button"
                className={view === 'aws' ? 'is-active' : ''}
                onClick={() => {
                  setView('aws');
                  setActiveNode(0);
                }}
              >
                AWS
              </button>
              <button
                type="button"
                className={view === 'k8s' ? 'is-active' : ''}
                onClick={() => {
                  setView('k8s');
                  setActiveNode(0);
                }}
              >
                Kubernetes
              </button>
            </div>

            <div className="mk-node-grid">
              {nodes.map((node, index) => (
                <button
                  key={node}
                  type="button"
                  className={activeNode === index ? 'is-active' : ''}
                  onClick={() => setActiveNode(index)}
                >
                  {node}
                </button>
              ))}
            </div>

            <p className="mk-signal">{signal}</p>
            <SafeLink className="mk-btn mk-btn-primary" href={siteLinks.interactiveDemo}>
              Try Interactive Demo
            </SafeLink>
          </article>
        </div>
      </div>
    </section>
  );
}
