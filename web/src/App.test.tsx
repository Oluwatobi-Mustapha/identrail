import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { App } from './App';

describe('App', () => {
  it('renders hero and top call-to-actions', () => {
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Machine Identity Reimagined'
      })
    ).toBeInTheDocument();

    expect(screen.getAllByRole('link', { name: 'Get Started (Open Source)' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('link', { name: 'Request Demo' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('link', { name: 'Star on GitHub' }).length).toBeGreaterThan(0);
  });

  it('renders the premium section flow', () => {
    render(<App />);

    expect(screen.getByRole('heading', { name: /One platform. Measurable machine identity outcomes./i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /From machine identity chaos to operating control/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Real security workflows, not just dashboards/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Trusted by teams securing production machine identities/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Integrations that fit your current stack/i })).toBeInTheDocument();
  });
});
