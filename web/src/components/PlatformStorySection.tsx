import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const pillars = [
  {
    title: 'Discover every machine identity edge',
    body: 'Continuously map service accounts, IAM roles, OIDC trust, and repository-exposed credentials in one graph.'
  },
  {
    title: 'Detect high-signal identity threats',
    body: 'Highlight exploitable trust paths and anomalous workload behavior before they become incidents.'
  },
  {
    title: 'Roll out policy safely',
    body: 'Simulate policy changes ahead of rollout and reduce production auth breakage with controlled enforcement.'
  }
] as const;

export function PlatformStorySection() {
  return (
    <section className="mk-section mk-platform" aria-labelledby="mk-platform-title">
      <div className="mk-shell">
        <div className="mk-section-head">
          <p className="mk-eyebrow">The Identrail Platform</p>
          <h2 id="mk-platform-title">From machine identity chaos to operating control</h2>
          <p>
            Identrail unifies discovery, detection, exposure scanning, and centralized authorization
            for AWS and Kubernetes environments.
          </p>
        </div>

        <div className="mk-pillars">
          {pillars.map((item) => (
            <article key={item.title}>
              <h3>{item.title}</h3>
              <p>{item.body}</p>
            </article>
          ))}
        </div>

        <div className="mk-row-cta">
          <SafeLink className="mk-btn mk-btn-secondary" href={siteLinks.platformOverview}>
            Explore Platform
          </SafeLink>
          <SafeLink className="mk-btn mk-btn-ghost" href={siteLinks.docs}>
            Read the Docs
          </SafeLink>
        </div>
      </div>
    </section>
  );
}
