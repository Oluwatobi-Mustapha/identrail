import { useEffect, useState } from 'react';
import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const navItems = [
  { label: 'Platform', href: siteLinks.platform },
  { label: 'Use Cases', href: siteLinks.useCases },
  { label: 'Docs', href: siteLinks.docs },
  { label: 'Resources', href: siteLinks.resources },
  { label: 'Blog', href: siteLinks.blog }
] as const;

export function MarketingHeader() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [bannerVisible, setBannerVisible] = useState(true);

  useEffect(() => {
    if (window.sessionStorage.getItem('identrail-banner-dismissed') === '1') {
      setBannerVisible(false);
    }
  }, []);

  return (
    <>
      {bannerVisible && (
        <div className="mk-banner" role="status" aria-live="polite">
          <p>
            Star us on GitHub • Now GA for Kubernetes
            <SafeLink href={siteLinks.starOnGithub}> See release notes</SafeLink>
          </p>
          <button
            type="button"
            aria-label="Dismiss announcement"
            onClick={() => {
              setBannerVisible(false);
              window.sessionStorage.setItem('identrail-banner-dismissed', '1');
            }}
          >
            ×
          </button>
        </div>
      )}

      <header className="mk-header" aria-label="Main navigation">
        <div className="mk-shell mk-header-inner">
          <SafeLink className="mk-brand" href="/" aria-label="Identrail home">
            <img src="/identrail-logo.png" alt="" width={30} height={30} />
            <span>
              <strong>Identrail</strong>
              <small>Machine Identity Security</small>
            </span>
          </SafeLink>

          <nav className="mk-nav" aria-label="Primary">
            {navItems.map((item) => (
              <SafeLink key={item.label} href={item.href}>
                {item.label}
              </SafeLink>
            ))}
          </nav>

          <div className="mk-header-cta">
            <SafeLink className="mk-btn mk-btn-ghost" href={siteLinks.starOnGithub}>
              Star on GitHub
            </SafeLink>
            <SafeLink className="mk-btn mk-btn-primary" href={siteLinks.requestDemo}>
              Request Demo
            </SafeLink>
          </div>

          <button
            type="button"
            className="mk-menu"
            aria-expanded={mobileOpen}
            aria-controls="mk-mobile-nav"
            onClick={() => setMobileOpen((open) => !open)}
          >
            Menu
          </button>
        </div>

        <nav id="mk-mobile-nav" className={`mk-mobile-nav ${mobileOpen ? 'is-open' : ''}`}>
          <div className="mk-shell">
            {navItems.map((item) => (
              <SafeLink key={item.label} href={item.href} onClick={() => setMobileOpen(false)}>
                {item.label}
              </SafeLink>
            ))}
            <SafeLink className="mk-btn mk-btn-ghost" href={siteLinks.starOnGithub}>
              Star on GitHub
            </SafeLink>
            <SafeLink className="mk-btn mk-btn-primary" href={siteLinks.requestDemo}>
              Request Demo
            </SafeLink>
          </div>
        </nav>
      </header>
    </>
  );
}
