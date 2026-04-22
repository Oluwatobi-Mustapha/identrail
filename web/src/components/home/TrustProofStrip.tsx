import { Link } from 'react-router-dom';
import { SafeLink } from '../SafeLink';
import { TRUST_PROOF_LINKS } from '../../content/proofArtifacts';

const TRUST_SUMMARY_ITEMS = TRUST_PROOF_LINKS.slice(0, 4);

export function TrustProofStrip() {
  return (
    <section className="idt-trust-strip" aria-label="Credibility and proof">
      <div className="idt-shell idt-proof-architecture">
        <p className="idt-proof-heading">Built in the open with verifiable trust controls.</p>
        <div className="idt-proof-architecture-list">
          {TRUST_SUMMARY_ITEMS.map((entry) => (
            <article key={entry.label} className="idt-proof-architecture-item">
              <p className="idt-proof-item-title">{entry.label}</p>
              <p>{entry.description}</p>
              {entry.external ? (
                <SafeLink href={entry.href} className="idt-proof-link">
                  Review
                </SafeLink>
              ) : (
                <Link to={entry.href} className="idt-proof-link">
                  Review
                </Link>
              )}
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
