import { Link } from 'react-router-dom';

const PATH_SUMMARY = 'GitHub Actions OIDC → AWS Role → K8s Service Account → RDS Billing Resource';

const PATH_STEPS = [
  'Source: GitHub Actions workflow identity',
  'Broker: OIDC trust relationship',
  'Privilege boundary: AWS IAM role assumption',
  'Target: production billing datastore'
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
        <p className="idt-hero-graph-title">Sample finding</p>
        <h3>High-risk production trust path</h3>
        <p className="idt-hero-path">{PATH_SUMMARY}</p>
        <div className="idt-hero-proof-meta">
          <span className="idt-severity-pill">High severity</span>
          <span>4-hop chain</span>
          <span>Read-only analysis</span>
        </div>
        <ol className="idt-hero-path-steps">
          {PATH_STEPS.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
        <Link to="/demo" className="idt-inline-link">
          Inspect this path in demo
        </Link>
      </aside>
    </div>
  );
}
