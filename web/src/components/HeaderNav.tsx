import { useEffect, useMemo, useState } from 'react';
import { githubRepo, siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const menuItems = [
  { label: 'Platform', href: siteLinks.platform },
  { label: 'Use Cases', href: siteLinks.useCases },
  { label: 'Docs', href: siteLinks.docs },
  { label: 'GitHub', href: siteLinks.github },
  { label: 'Blog', href: siteLinks.blog }
];

function formatStars(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(1)}k`;
  return String(count);
}

export function HeaderNav() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [starCount, setStarCount] = useState<number | null>(null);
  const [bannerVisible, setBannerVisible] = useState(true);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 6);
    const onResize = () => {
      if (window.innerWidth > 992) setMobileOpen(false);
    };

    onScroll();
    window.addEventListener('scroll', onScroll);
    window.addEventListener('resize', onResize);

    return () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onResize);
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`https://api.github.com/repos/${githubRepo.owner}/${githubRepo.name}`, {
      signal: controller.signal,
      headers: { Accept: 'application/vnd.github+json' }
    })
      .then(async (response) => {
        if (!response.ok) return null;
        const payload = (await response.json()) as { stargazers_count?: number };
        return typeof payload.stargazers_count === 'number' ? payload.stargazers_count : null;
      })
      .then((count) => {
        if (count !== null) setStarCount(count);
      })
      .catch(() => undefined);

    return () => controller.abort();
  }, []);

  useEffect(() => {
    const dismissed = window.sessionStorage.getItem('identrail-banner-dismissed');
    if (dismissed === '1') setBannerVisible(false);
  }, []);

  const starLabel = useMemo(
    () => (starCount === null ? 'Star on GitHub' : `Star on GitHub (${formatStars(starCount)})`),
    [starCount]
  );

  return (
    <>
      {bannerVisible && (
        <div className="announcement-bar" role="status" aria-live="polite">
          <span>Star us on GitHub • Now GA for Kubernetes.</span>
          <SafeLink href={siteLinks.starOnGithub}>Give a star</SafeLink>
          <button
            type="button"
            className="announcement-close"
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

      <header className={`site-header ${scrolled ? 'is-sticky' : ''}`}>
        <div className="header-inner">
          <SafeLink className="brand" href="/" aria-label="Identrail home">
            <span className="brand-mark" aria-hidden="true">
              <img
                className="brand-logo"
                src="/identrail-logo.png"
                alt=""
                width={28}
                height={28}
                loading="eager"
                decoding="async"
              />
            </span>
            <span>
              <span className="brand-wordmark">Identrail</span>
              <span className="brand-tagline">Machine Identity Security</span>
            </span>
          </SafeLink>

          <nav className="desktop-nav" aria-label="Primary">
            <ul>
              {menuItems.map((item) => (
                <li key={item.label}>
                  <SafeLink href={item.href}>{item.label}</SafeLink>
                </li>
              ))}
            </ul>
          </nav>

          <div className="desktop-cta">
            <SafeLink className="btn btn-ghost" href={siteLinks.starOnGithub}>
              {starLabel}
            </SafeLink>
            <SafeLink className="btn btn-primary" href={siteLinks.requestDemo}>
              Request Demo
            </SafeLink>
          </div>

          <button
            className="mobile-menu-button"
            type="button"
            aria-label="Toggle menu"
            aria-expanded={mobileOpen}
            aria-controls="mobile-nav"
            onClick={() => setMobileOpen((value) => !value)}
          >
            Menu
          </button>
        </div>

        <nav id="mobile-nav" className={`mobile-nav ${mobileOpen ? 'open' : ''}`} aria-label="Mobile">
          <ul>
            {menuItems.map((item) => (
              <li key={item.label}>
                <SafeLink href={item.href} onClick={() => setMobileOpen(false)}>
                  {item.label}
                </SafeLink>
              </li>
            ))}
          </ul>
          <div className="mobile-nav-cta">
            <SafeLink className="btn btn-ghost" href={siteLinks.starOnGithub}>
              {starLabel}
            </SafeLink>
            <SafeLink className="btn btn-primary" href={siteLinks.requestDemo}>
              Request Demo
            </SafeLink>
          </div>
        </nav>
      </header>
    </>
  );
}
