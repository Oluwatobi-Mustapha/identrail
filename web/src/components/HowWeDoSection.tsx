import { howWeDoCards } from '../siteContent';
import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';
import { TrustGraphIllustration } from './TrustGraphIllustration';

export function HowWeDoSection() {
  return (
    <section className="section" aria-labelledby="how-we-do-title">
      <div className="section-header centered">
        <p className="eyebrow eyebrow-dark">How We Do It</p>
        <h2 id="how-we-do-title">Operational machine identity security at scale</h2>
      </div>

      <div className="card-grid three-up how-grid">
        {howWeDoCards.map((item) => (
          <article key={item.title} className="content-card how-card">
            <h3>{item.title}</h3>
            <p>{item.body}</p>
          </article>
        ))}
      </div>

      <div className="how-proof" aria-label="How we do it proof block">
        <blockquote>
          <p>
            “Identrail gave us a practical path from machine identity visibility to production-safe
            authorization control.”
          </p>
          <footer>
            <strong>Principal Security Architect</strong>
            <span>Fortune 100 infrastructure team</span>
          </footer>
        </blockquote>

        <div className="how-video-placeholder" role="img" aria-label="Video placeholder for platform walkthrough">
          <TrustGraphIllustration
            className="trust-graph-compact"
            label="Abstract walkthrough trust graph illustration"
          />
          <span>2-minute platform walkthrough placeholder</span>
        </div>
      </div>

      <div className="centered-action">
        <SafeLink className="btn btn-secondary" href={siteLinks.howWeDoIt}>
          Learn How It Works
        </SafeLink>
        <SafeLink className="btn btn-text" href={siteLinks.docs}>
          Read the Docs
        </SafeLink>
      </div>
    </section>
  );
}
