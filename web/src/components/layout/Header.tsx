import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { SafeLink } from '../SafeLink';

type NavLinkItem = {
  to: string;
  label: string;
};

export function Header({
  navLinks,
  githubRepo,
  theme,
  onToggleTheme
}: {
  navLinks: readonly NavLinkItem[];
  githubRepo: string;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!menuOpen) {
      return;
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false);
      }
    };

    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [menuOpen]);

  return (
    <header className="idt-header">
      <div className="idt-shell idt-header-row">
        <Link to="/" className="idt-brand" aria-label="Identrail homepage">
          <img src="/identrail-logo.png" width="32" height="32" alt="Identrail" decoding="async" />
          <span>
            Identrail
            <small>Machine Identity Security</small>
          </span>
        </Link>

        <button
          className="idt-menu-toggle"
          type="button"
          onClick={() => setMenuOpen((prev) => !prev)}
          aria-expanded={menuOpen}
          aria-controls="primary-nav"
          aria-label={menuOpen ? 'Close primary navigation' : 'Open primary navigation'}
        >
          <span className="idt-menu-toggle-icon" aria-hidden="true" />
          <span className="idt-menu-toggle-label">{menuOpen ? 'Close' : 'Menu'}</span>
        </button>

        <nav id="primary-nav" className={`idt-nav ${menuOpen ? 'is-open' : ''}`} aria-label="Primary">
          {navLinks.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => (isActive ? 'is-active' : '')}
              onClick={() => setMenuOpen(false)}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="idt-header-actions">
          <button
            type="button"
            className={`idt-theme-toggle ${theme === 'light' ? 'is-light' : ''}`}
            onClick={onToggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? (
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path
                  fill="currentColor"
                  d="M6.76 4.84 5.35 3.43 3.93 4.84l1.42 1.41 1.41-1.41Zm10.49 0 1.41-1.41 1.41 1.41-1.41 1.41-1.41-1.41ZM12 4h1V1h-2v3h1Zm7 9h3v-2h-3v2Zm-7 7h1v3h-2v-3h1ZM2 13h3v-2H2v2Zm3.34 6.57 1.41 1.41 1.41-1.41-1.41-1.41-1.41 1.41Zm13.31 1.41 1.41-1.41-1.41-1.41-1.41 1.41 1.41 1.41ZM12 6a6 6 0 1 0 0 12 6 6 0 0 0 0-12Z"
                />
              </svg>
            ) : (
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path
                  fill="currentColor"
                  d="M20.74 15.35A9.6 9.6 0 0 1 8.65 3.26a.75.75 0 0 0-.92-.93A10.98 10.98 0 1 0 21.67 16.27a.75.75 0 0 0-.93-.92Z"
                />
              </svg>
            )}
            <span>{theme === 'dark' ? 'Light' : 'Dark'}</span>
          </button>

          <Link to="/read-only-scan" className="idt-btn idt-btn-primary" data-ab-slot="header_primary_cta">
            Start Free Risk Scan
          </Link>
          <Link to="/demo" className="idt-btn idt-btn-dark">
            Book Demo
          </Link>
          <SafeLink href={githubRepo} className="idt-header-utility">
            GitHub
          </SafeLink>
        </div>
      </div>
    </header>
  );
}
