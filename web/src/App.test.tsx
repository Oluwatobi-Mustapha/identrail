import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { App } from './App';

describe('App', () => {
  it('renders homepage hero and conversion CTAs', () => {
    window.history.pushState({}, '', '/');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Machine Identities, Fully Visible. Risks, Fully Controlled.'
      })
    ).toBeInTheDocument();

    expect(screen.getAllByRole('link', { name: /Try Free Hosted SaaS|Start Free Risk Scan/i }).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: 'Star on GitHub' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Book 15-min Demo' })).toBeInTheDocument();
    expect(screen.getByText(/Choose deployment:/i)).toBeInTheDocument();
  });

  it('renders pricing page routes and key elements', () => {
    window.history.pushState({}, '', '/pricing');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Choose your rollout path: open source, hosted pro, or enterprise/i
      })
    ).toBeInTheDocument();

    expect(screen.getByRole('button', { name: /Annual/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Contact Sales' })).toBeInTheDocument();
  });
});
