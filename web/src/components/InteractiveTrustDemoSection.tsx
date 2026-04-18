import { useMemo, useState } from 'react';
import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

type DemoView = 'aws' | 'kubernetes';

const demoData: Record<
  DemoView,
  Array<{ id: string; label: string; trustPath: string; risk: string; severity: 'low' | 'medium' | 'high' }>
> = {
  aws: [
    {
      id: 'aws-sa',
      label: 'CI Role',
      trustPath: 'CI Role → OIDC Provider → Production Deploy Role',
      risk: 'Wildcard assume-role path detected on production account.',
      severity: 'high'
    },
    {
      id: 'aws-oidc',
      label: 'OIDC',
      trustPath: 'OIDC Provider → Build Role → Artifact Bucket',
      risk: 'Unrestricted audience claim allows token replay.',
      severity: 'medium'
    },
    {
      id: 'aws-kms',
      label: 'KMS',
      trustPath: 'Deploy Role → KMS Key → Secret Decrypt',
      risk: 'Broad kms:Decrypt grants leaked across environments.',
      severity: 'high'
    }
  ],
  kubernetes: [
    {
      id: 'k8s-sa',
      label: 'ServiceAccount',
      trustPath: 'Workload SA → ClusterRoleBinding → Namespace Admin',
      risk: 'Namespace admin inherits cluster-level secret read.',
      severity: 'high'
    },
    {
      id: 'k8s-rb',
      label: 'RoleBinding',
      trustPath: 'RoleBinding → Pod Exec → Runtime Token Mount',
      risk: 'Pod exec access enables lateral trust-path escalation.',
      severity: 'medium'
    },
    {
      id: 'k8s-secret',
      label: 'Secret',
      trustPath: 'Secret Store → Build Agent → External Registry',
      risk: 'Unused secret still reachable from legacy build agent.',
      severity: 'low'
    }
  ]
};

export function InteractiveTrustDemoSection() {
  const [view, setView] = useState<DemoView>('aws');
  const [selectedId, setSelectedId] = useState<string>(demoData.aws[0].id);
  const nodes = demoData[view];
  const selected = useMemo(
    () => nodes.find((node) => node.id === selectedId) ?? nodes[0],
    [nodes, selectedId]
  );

  return (
    <section className="section reveal-on-scroll" aria-labelledby="interactive-demo-title">
      <div className="section-card interactive-demo">
        <div className="section-header">
          <p className="eyebrow eyebrow-dark">Interactive Demo</p>
          <h2 id="interactive-demo-title">Try the Identrail Trust Graph Live</h2>
        </div>

        <div className="interactive-demo-layout">
          <div>
            <div className="interactive-toggle" role="tablist" aria-label="Trust graph demo view toggle">
              <button
                type="button"
                role="tab"
                aria-selected={view === 'aws'}
                className={view === 'aws' ? 'active' : ''}
                onClick={() => {
                  setView('aws');
                  setSelectedId(demoData.aws[0].id);
                }}
              >
                AWS View
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={view === 'kubernetes'}
                className={view === 'kubernetes' ? 'active' : ''}
                onClick={() => {
                  setView('kubernetes');
                  setSelectedId(demoData.kubernetes[0].id);
                }}
              >
                Kubernetes View
              </button>
            </div>

            <div className="interactive-node-canvas" role="group" aria-label="Clickable trust graph nodes">
              {nodes.map((node) => (
                <button
                  key={node.id}
                  type="button"
                  className={`interactive-node ${selected.id === node.id ? 'selected' : ''} ${node.severity}`}
                  onClick={() => setSelectedId(node.id)}
                >
                  {node.label}
                </button>
              ))}
            </div>
          </div>

          <aside className="interactive-inspector" aria-live="polite">
            <p className="interactive-label">Expanded trust path</p>
            <h3>{selected.trustPath}</h3>
            <p>{selected.risk}</p>
            <p className={`interactive-risk ${selected.severity}`}>Simulated finding: {selected.severity} risk</p>
          </aside>
        </div>

        <SafeLink className="btn btn-primary" href={siteLinks.interactiveDemo}>
          Try Interactive Demo (self-hosted in &lt;10s with docker compose up)
        </SafeLink>
      </div>
    </section>
  );
}
