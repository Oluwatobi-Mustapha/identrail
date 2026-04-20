import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';
import { TrustGraphIllustration } from './TrustGraphIllustration';

export function AccessGraphSection() {
  return (
    <section className="section" aria-labelledby="access-graph-title">
      <div className="section-layout split">
        <div>
          <h2 id="access-graph-title">Introducing the Identrail Access Graph</h2>
          <p className="section-lead">
            See which machine identity can take what action on which resource across your cloud and
            Kubernetes estate.
          </p>
          <p>
            Identrail unifies identities and entitlements across workloads, service accounts, roles,
            and external integrations, giving teams a single source of truth for effective machine
            access.
          </p>
          <SafeLink className="btn btn-secondary" href={siteLinks.accessGraph}>
            Learn More
          </SafeLink>
        </div>

        <div className="access-graph-preview">
          <TrustGraphIllustration
            className="trust-graph-surface"
            label="Abstract access graph node and edge visualization"
          />
          <p className="access-graph-caption">Live trust path correlation across cloud and Kubernetes.</p>
        </div>
      </div>
    </section>
  );
}
