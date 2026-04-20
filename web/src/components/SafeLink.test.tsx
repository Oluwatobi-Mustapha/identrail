import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { SafeLink } from './SafeLink';

describe('SafeLink', () => {
  it('opens external links in a new tab with safe rel defaults', () => {
    render(<SafeLink href="https://github.com/Oluwatobi-Mustapha/identrail">GitHub</SafeLink>);

    const link = screen.getByRole('link', { name: 'GitHub' });
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel');
    expect(link.getAttribute('rel')).toContain('noopener');
    expect(link.getAttribute('rel')).toContain('noreferrer');
  });

  it('keeps same-tab behavior for internal paths and hash anchors', () => {
    render(
      <>
        <SafeLink href="/docs">Docs</SafeLink>
        <SafeLink href="#main-content">Skip</SafeLink>
      </>
    );

    expect(screen.getByRole('link', { name: 'Docs' })).not.toHaveAttribute('target');
    expect(screen.getByRole('link', { name: 'Skip' })).not.toHaveAttribute('target');
  });

  it('respects explicit target overrides', () => {
    render(
      <SafeLink href="/docs" target="_self">
        Docs
      </SafeLink>
    );

    expect(screen.getByRole('link', { name: 'Docs' })).toHaveAttribute('target', '_self');
  });
});
