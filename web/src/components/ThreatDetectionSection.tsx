import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const anomalyNodes = [
  { label: 'EKS SA', tone: 'normal' },
  { label: 'OIDC', tone: 'normal' },
  { label: 'IAM Role', tone: 'alert' },
  { label: 'Vault', tone: 'normal' },
  { label: 'S3', tone: 'normal' },
  { label: 'Build Token', tone: 'alert' }
] as const;

export function ThreatDetectionSection() {
  return (
    <section className="section reveal-on-scroll" aria-labelledby="threat-detection-title">
      <div className="section-card threat-detection-shell">
        <div className="threat-detection-copy">
          <p className="eyebrow eyebrow-dark">Identrail NHIDR™</p>
          <h2 id="threat-detection-title">Real-Time Threat Detection</h2>
          <p>
            Monitor behavioral anomalies across machine identities and trust paths with continuous
            graph-level detection that surfaces risky drift in seconds.
          </p>
          <p className="threat-live-counter" aria-live="polite">
            <span className="live-dot" aria-hidden="true" />
            12 anomalies detected in the last 60 seconds
          </p>
          <SafeLink className="btn btn-primary" href={siteLinks.detectionEngine}>
            Explore the open-source detection engine on GitHub
          </SafeLink>
        </div>

        <div className="threat-detection-visual" role="img" aria-label="Real-time threat graph with anomaly overlay">
          <div className="threat-edges" aria-hidden="true" />
          <div className="threat-node-grid">
            {anomalyNodes.map((node) => (
              <span key={node.label} className={`threat-node ${node.tone}`}>
                {node.label}
              </span>
            ))}
          </div>
          <aside className="threat-overlay">
            <strong>Behavioral anomaly detected</strong>
            <p>Idle service account in EKS attempted cross-account role assumption.</p>
            <span>Severity: High • Correlated by trust graph</span>
          </aside>
        </div>
      </div>
    </section>
  );
}
