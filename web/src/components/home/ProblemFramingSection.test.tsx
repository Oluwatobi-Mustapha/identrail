import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ProblemFramingSection } from './ProblemFramingSection';

describe('ProblemFramingSection', () => {
  it('keeps the risk story focused on owner-ready outputs', () => {
    render(<ProblemFramingSection />);

    expect(
      screen.getByRole('heading', { name: 'Connect identity signals. Reveal the path.' })
    ).toBeInTheDocument();
    expect(screen.queryByText('Why teams miss machine identity risk')).not.toBeInTheDocument();
    expect(screen.queryByText(/Identrail joins identity evidence/)).not.toBeInTheDocument();
    expect(screen.getByText('From signal to owner-ready fix')).toBeInTheDocument();
    expect(screen.getByText('Risk graph output')).toBeInTheDocument();
    expect(screen.getByText('Reachable impact')).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Risk evidence workflow' })).not.toBeInTheDocument();
  });
});
