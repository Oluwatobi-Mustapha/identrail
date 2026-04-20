import { platformCapabilities } from '../siteContent';
import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

export function PlatformSection() {
  return (
    <section className="section" id="platform" aria-labelledby="platform-title">
      <div className="section-card">
        <div className="section-header">
          <h2 id="platform-title">The Identrail Platform</h2>
          <p>
            Identrail discovers machine identities and trust paths across AWS and Kubernetes,
            detects high-signal identity risks, scans repositories for exposure, and supports
            centralized authorization with rollout-safe policy controls.
          </p>
          <SafeLink className="btn btn-secondary" href={siteLinks.platformOverview}>
            Explore Platform
          </SafeLink>
        </div>

        <div className="platform-grid">
          {platformCapabilities.map((item) => (
            <article key={item.title} className="platform-card">
              <h3>{item.title}</h3>
              <p>{item.body}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
