import { integrations } from '../siteContent';
import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

export function IntegrationsSection() {
  return (
    <section className="section" aria-labelledby="integrations-title">
      <div className="section-header centered">
        <h2 id="integrations-title">Integrations for all enterprise systems</h2>
        <p>
          Connect Identrail to cloud, Kubernetes, repository, and observability systems without
          changing your existing delivery workflows.
        </p>
      </div>

      <div className="integrations-grid" role="list" aria-label="Integrations logo wall">
        {integrations.map((name) => (
          <SafeLink key={name} role="listitem" href={siteLinks.integrations} className="integration-card">
            <span className="integration-mark" aria-hidden="true" />
            <span>{name}</span>
          </SafeLink>
        ))}
      </div>

      <div className="centered-action">
        <SafeLink className="btn btn-text" href={siteLinks.integrations}>
          See all integrations
        </SafeLink>
      </div>
    </section>
  );
}
