import { useMemo, useState } from 'react';

const trustNodes = ['EKS SA', 'OIDC', 'IAM Role', 'KMS', 'S3', 'Build Token'] as const;

const baseLog = [
  'Revoked access to arn:aws:iam::prod:role/ci-runner at 12:31 UTC',
  'Revoked access to arn:aws:iam::prod:role/eks-default at 12:31 UTC',
  'Revoked access to arn:aws:iam::shared:role/oidc-federation at 12:31 UTC',
  'Revoked access to arn:aws:iam::data:role/s3-replication at 12:31 UTC',
  'Revoked access to arn:aws:iam::prod:role/secrets-reader at 12:31 UTC'
] as const;

export function KillSwitchSection() {
  const [revoked, setRevoked] = useState(false);
  const logs = useMemo(() => [...baseLog, ...baseLog], []);

  return (
    <section className="section reveal-on-scroll" aria-labelledby="kill-switch-title">
      <div className={`section-card kill-switch-shell ${revoked ? 'is-revoked' : ''}`}>
        <div className="kill-switch-copy">
          <p className="eyebrow eyebrow-dark">Policy Simulation + Emergency Control</p>
          <h2 id="kill-switch-title">Instant Revocation &amp; Kill Switch</h2>
          <p>
            One-click kill switch for any machine identity — open-source and self-hosted.
            Immediately sever risky trust edges and generate an audit trail for response teams.
          </p>
          <button
            type="button"
            className="kill-switch-button"
            aria-pressed={revoked}
            onClick={() => setRevoked((value) => !value)}
          >
            REVOKE ALL ACCESS
          </button>
          <p className="kill-switch-note">
            Hover or click to simulate immediate revocation across AWS and Kubernetes trust paths.
          </p>
        </div>

        <div className="kill-switch-visuals">
          <div className="kill-switch-graph" role="img" aria-label="Revocation graph simulation">
            {trustNodes.map((node) => (
              <span key={node} className="kill-node">
                {node}
              </span>
            ))}
          </div>

          <div className="kill-switch-log" aria-label="Live revocation log">
            <p>Live audit stream</p>
            <div className="kill-switch-log-track">
              {logs.map((line, index) => (
                <span key={`${line}-${index}`}>{line}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
