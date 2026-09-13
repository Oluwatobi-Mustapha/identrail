import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ProblemFramingSection } from './ProblemFramingSection';

describe('ProblemFramingSection', () => {
  it('keeps the risk story focused on owner-ready outputs', () => {
    render(<ProblemFramingSection />);

    expect(
      screen.getByRole('heading', { name: 'Signals only matter when they reveal the path.' })
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        'Identrail joins identity evidence into one path, so teams can see blast radius, ownership, and the safest fix.'
      )
    ).toBeInTheDocument();
    expect(screen.getByText('From signal to owner-ready fix')).toBeInTheDocument();
    expect(screen.getByText('Risk graph output')).toBeInTheDocument();
    expect(screen.getByText('Reachable impact')).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Risk evidence workflow' })).not.toBeInTheDocument();
  });
});
