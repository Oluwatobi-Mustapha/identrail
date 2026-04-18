import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const columns = [
  {
    title: 'Platform',
    links: [
      ['Access Graph', siteLinks.accessGraph],
      ['Policy Simulation', siteLinks.policyDocs],
      ['Threat Detection', siteLinks.detectionEngine],
      ['Integrations', siteLinks.integrations]
    ]
  },
  {
    title: 'Use Cases',
    links: [
      ['Machine Identity Posture', '/use-cases/machine-identity-posture'],
      ['Trust Path Analysis', '/use-cases/trust-path-analysis'],
      ['Repo Exposure Monitoring', '/use-cases/repository-exposure-monitoring'],
      ['Agentic AI Security', siteLinks.agenticAi]
    ]
  },
  {
    title: 'Resources',
    links: [
      ['Docs', siteLinks.docs],
      ['Blog', siteLinks.blog],
      ['Security', siteLinks.security],
      ['Trust Center', siteLinks.trustCenter]
    ]
  },
  {
    title: 'Open Source',
    links: [
      ['GitHub', siteLinks.github],
      ['Star on GitHub', siteLinks.starOnGithub],
      ['Contribute', siteLinks.contribute],
      ['docker compose up', siteLinks.quickstartDocker]
    ]
  }
] as const;

const socialLinks = [
  {
    label: 'LinkedIn',
    href: siteLinks.linkedin,
    className: 'linkedin',
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M6.94 8.5V21H3.56V8.5h3.38Zm.22-3.86a1.95 1.95 0 1 1-3.9 0 1.95 1.95 0 0 1 3.9 0ZM21 13.83V21h-3.36v-6.72c0-1.6-.57-2.7-2-2.7-1.1 0-1.75.74-2.04 1.45-.1.26-.13.63-.13 1V21h-3.36s.04-11.27 0-12.5h3.36v1.77c.45-.7 1.26-1.69 3.07-1.69 2.24 0 3.92 1.46 3.92 4.6Z" />
      </svg>
    )
  },
  {
    label: 'X',
    href: siteLinks.x,
    className: 'x',
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="m18.9 2.25h3.45l-7.54 8.62 8.86 10.88h-6.94l-5.43-6.58-5.76 6.58H2.08l8.07-9.22L1.64 2.25h7.11l4.9 6.02 5.25-6.02Zm-1.22 17.42h1.91L7.72 4.22H5.67Z" />
      </svg>
    )
  },
  {
    label: 'Discord',
    href: siteLinks.discord,
    className: 'discord',
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M5.25 7.2c1.9-1.12 4.2-1.8 6.75-1.8s4.85.68 6.75 1.8c.96 1.96 1.44 4.06 1.44 6.3-1.56 1.2-3.2 2.1-4.95 2.73l-1.05-1.73c.73-.25 1.45-.56 2.18-.93l-.5-.3a9.95 9.95 0 0 1-7.74 0l-.5.3c.73.37 1.45.68 2.18.93L8.76 16.2a17.7 17.7 0 0 1-4.95-2.73c0-2.24.48-4.34 1.44-6.27ZM9.23 11.6c0-.8-.55-1.45-1.25-1.45-.72 0-1.28.66-1.28 1.45 0 .8.56 1.44 1.28 1.44.7 0 1.25-.65 1.25-1.44Zm8.06 0c0-.8-.55-1.45-1.25-1.45-.72 0-1.28.66-1.28 1.45 0 .8.56 1.44 1.28 1.44.7 0 1.25-.65 1.25-1.44Z" />
      </svg>
    )
  }
] as const;

export function MarketingFooter() {
  return (
    <footer className="mk-footer">
      <div className="mk-shell mk-footer-top">
        <div className="mk-footer-brand">
          <img src="/identrail-logo.png" alt="" width={32} height={32} />
          <div>
            <strong>Identrail</strong>
            <p>Open-source machine identity security for AWS and Kubernetes.</p>
          </div>
        </div>

        <div className="mk-footer-columns">
          {columns.map((column) => (
            <section key={column.title}>
              <h2>{column.title}</h2>
              {column.links.map(([label, href]) => (
                <SafeLink key={label} href={href}>
                  {label}
                </SafeLink>
              ))}
            </section>
          ))}
        </div>
      </div>

      <div className="mk-shell mk-footer-bottom">
        <div className="mk-footer-meta">
          <p>© 2026 Identrail. All rights reserved.</p>
          <nav aria-label="Legal">
            <SafeLink href={siteLinks.legalTerms}>Terms of Use</SafeLink>
            <SafeLink href={siteLinks.legalPrivacy}>Privacy Policy</SafeLink>
          </nav>
        </div>

        <div className="mk-footer-social" aria-label="Social links">
          {socialLinks.map((social) => (
            <SafeLink
              key={social.label}
              className={`mk-social-icon ${social.className}`}
              href={social.href}
              aria-label={`Identrail on ${social.label}`}
            >
              {social.icon}
            </SafeLink>
          ))}
        </div>
      </div>
    </footer>
  );
}
