import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';
import { TrustGraphIllustration } from './TrustGraphIllustration';

const technicalCards = [
  {
    title: 'Reachable Trust Path',
    body: 'Trace exactly how one machine identity can traverse roles, service accounts, and policies to reach sensitive resources.',
    link: siteLinks.technicalDocs
  },
  {
    title: 'Findings Queue',
    body: 'Prioritized machine-identity findings with severity, blast radius context, and remediation guidance for security teams.',
    link: siteLinks.findingsDocs
  },
  {
    title: 'Policy Simulation',
    body: 'Preview policy impact before rollout to validate least-privilege controls and prevent production authorization breakage.',
    link: siteLinks.policyDocs
  },
  {
    title: 'Repo Scanner',
    body: 'Continuously scan repositories for leaked credentials and risky trust assumptions tied to machine identities.',
    link: siteLinks.repoScannerDocs
  }
] as const;

export function TechnicalConsoleSection() {
  return (
    <section className="section reveal-on-scroll" aria-labelledby="technical-console-title">
      <div className="section-card technical-console-shell">
        <div className="section-header">
          <p className="eyebrow eyebrow-dark">Technical Console (Preserved)</p>
          <h2 id="technical-console-title">Deep technical workflows stay fully visible</h2>
          <p>
            The marketing layer now leads the page, but Identrail still exposes full-depth
            technical workflows for security and platform engineering teams.
          </p>
        </div>

        <div className="technical-console-layout">
          <TrustGraphIllustration
            className="trust-graph-surface"
            label="Technical trust graph preview for console workflows"
          />

          <div className="technical-console-grid">
            {technicalCards.map((card) => (
              <article key={card.title} className="technical-console-card">
                <h3>{card.title}</h3>
                <p>{card.body}</p>
                <SafeLink href={card.link}>Read technical details</SafeLink>
              </article>
            ))}
          </div>
        </div>

        <div className="technical-console-cta">
          <code>docker compose up</code>
          <SafeLink href={siteLinks.starOnGithub}>Star on GitHub</SafeLink>
          <SafeLink href={siteLinks.docs}>Read the Docs</SafeLink>
          <SafeLink href={siteLinks.contribute}>Contribute</SafeLink>
        </div>
      </div>
    </section>
  );
}
