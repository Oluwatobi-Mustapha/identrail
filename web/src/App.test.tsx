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
        name: 'See which machine identities can actually reach production.'
      })
    ).toBeInTheDocument();

    expect(screen.getAllByRole('link', { name: 'Start Read-Only Risk Scan' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('link', { name: 'Book Technical Demo' }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Adoption Paths/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Reachable Risk Paths/i).length).toBeGreaterThan(0);
  });

  it('renders pricing page routes and key elements', () => {
    window.history.pushState({}, '', '/pricing');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Pricing aligned to how teams adopt machine identity security/i
      })
    ).toBeInTheDocument();

    expect(screen.getByRole('button', { name: /Annual/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Contact Sales' })).toBeInTheDocument();
  });

  it('renders read-only scan intake flow route', () => {
    window.history.pushState({}, '', '/read-only-scan');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Start a machine identity risk scan with deployment-safe onboarding/i
      })
    ).toBeInTheDocument();

    expect(screen.getByText(/Step 1 of 3/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Continue' })).toBeInTheDocument();
  });

  it('renders deployment models route', () => {
    window.history.pushState({}, '', '/deployment-models');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Choose your control boundary without changing operating model/i
      })
    ).toBeInTheDocument();
  });

  it('renders integrations route', () => {
    window.history.pushState({}, '', '/integrations');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Identity signal coverage across cloud, cluster, and code workflows/i
      })
    ).toBeInTheDocument();
  });
});
