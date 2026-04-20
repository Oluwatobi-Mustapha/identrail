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
        name: 'Identify risky AWS IAM, Kubernetes, and GitHub trust paths before attackers use them.'
      })
    ).toBeInTheDocument();

    expect(screen.getAllByRole('link', { name: 'Start Free Risk Scan' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('link', { name: 'Book Demo' }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Adoption Paths/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Kubernetes service account can assume production AWS role/i).length).toBeGreaterThan(0);
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
