import { Link } from 'react-router-dom';
import { SafeLink } from '../SafeLink';
import { TRUST_PROOF_LINKS } from '../../content/proofArtifacts';

export function TrustProofStrip() {
  return (
    <section className="idt-trust-strip" aria-label="Credibility and proof">
      <div className="idt-shell">
        <p>Validate the product before you commit: inspect architecture, outputs, and security process.</p>
        <div className="idt-logo-row idt-proof-row">
          {TRUST_PROOF_LINKS.map((entry) => (
            <article key={entry.label} className="idt-proof-item">
              {entry.external ? (
                <SafeLink href={entry.href} className="idt-proof-link">
                  {entry.label}
                </SafeLink>
              ) : (
                <Link to={entry.href} className="idt-proof-link">
                  {entry.label}
                </Link>
              )}
              <p>{entry.description}</p>
              <small>{entry.freshness}</small>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
