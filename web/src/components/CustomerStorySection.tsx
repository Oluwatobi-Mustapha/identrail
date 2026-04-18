import { customerQuotes } from '../siteContent';
import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';
import { TrustGraphIllustration } from './TrustGraphIllustration';

export function CustomerStorySection() {
  return (
    <section className="section" aria-labelledby="customer-story-title">
      <div className="section-header centered">
        <h2 id="customer-story-title">Hear from our customers</h2>
      </div>

      <div className="customer-story-layout">
        <div className="quote-grid">
          {customerQuotes.map((item) => (
            <blockquote key={item.author} className="quote-card">
              <p>“{item.quote}”</p>
              <footer>
                <strong>{item.author}</strong>
                <span>{item.role}</span>
              </footer>
            </blockquote>
          ))}
        </div>

        <article className="video-story-card">
          <h3>Machine identity security in practice</h3>
          <p>
            See how security and platform teams use Identrail to expose trust-path risk, enforce
            least privilege, and ship rollout-safe authorization controls.
          </p>
          <div className="video-shell" aria-label="Customer video placeholder">
            <TrustGraphIllustration
              className="trust-graph-compact"
              label="Customer story video placeholder trust graph illustration"
            />
            <span className="video-placeholder-label">Customer video placeholder</span>
          </div>
          <SafeLink className="btn btn-secondary" href={siteLinks.watchDemo}>
            Watch full customer story
          </SafeLink>
        </article>
      </div>
    </section>
  );
}
