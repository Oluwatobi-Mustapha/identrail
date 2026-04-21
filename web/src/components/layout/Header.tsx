import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { captureAnalyticsEvent } from '../../analytics/events';

type NavLinkItem = {
  to: string;
  label: string;
};

export function Header({ navLinks }: { navLinks: readonly NavLinkItem[] }) {
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
          aria-label="Toggle primary navigation"
        >
          Menu
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
          <Link
            to="/read-only-scan"
            className="idt-btn idt-btn-primary"
            data-ab-slot="header_primary_cta"
            onClick={() => captureAnalyticsEvent('cta_header_read_only_scan_click', { placement: 'header' })}
          >
            Start Read-Only Risk Scan
          </Link>
          <Link
            to="/demo"
            className="idt-btn idt-btn-dark"
            onClick={() => captureAnalyticsEvent('cta_header_technical_demo_click', { placement: 'header' })}
          >
            Book Technical Demo
          </Link>
        </div>
      </div>
    </header>
  );
}
