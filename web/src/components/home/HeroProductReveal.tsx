import { Link } from 'react-router-dom';

const PATH_SUMMARY = 'GitHub Actions OIDC → AWS Role → K8s Service Account → RDS Billing Resource';

const PROOF_ITEMS = [
  { label: 'Blast radius', value: '11 production resources reachable' },
  { label: 'Exposure type', value: 'Federated identity chain with broad role trust' },
  { label: 'Safe first action', value: 'Constrain role trust subject claims, then simulate rollout' }
] as const;

export function HeroProductReveal() {
  return (
    <div className="idt-graph-visual" aria-label="Trust path product preview">
      <div className="idt-graph-grid" />
      <div className="idt-node idt-node-root">GitHub Actions OIDC</div>
      <div className="idt-node idt-node-role">AWS Role: billing-prod</div>
      <div className="idt-node idt-node-k8s">K8s SA: payments-api</div>
      <div className="idt-node idt-node-repo">RDS: billing-ledger</div>
      <span className="idt-edge idt-edge-a" />
      <span className="idt-edge idt-edge-b" />
      <span className="idt-edge idt-edge-c" />
      <span className="idt-pulse idt-pulse-a" />
      <span className="idt-pulse idt-pulse-b" />

      <aside className="idt-hero-graph-caption idt-hero-proof-card">
        <p className="idt-hero-graph-title">Selected risk path</p>
        <p className="idt-hero-path">{PATH_SUMMARY}</p>
        <div className="idt-hero-proof-meta">
          <span className="idt-severity-pill">High</span>
          <span>4-hop chain</span>
          <span>Read-only analysis</span>
        </div>
        <dl className="idt-hero-proof-list">
          {PROOF_ITEMS.map((item) => (
            <div key={item.label}>
              <dt>{item.label}</dt>
              <dd>{item.value}</dd>
            </div>
          ))}
        </dl>
        <Link to="/demo" className="idt-inline-link">
          Open technical demo
        </Link>
      </aside>
    </div>
  );
}
