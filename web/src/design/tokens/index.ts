export const designTokens = {
  color: {
    surface: {
      canvas: 'var(--surface-canvas)',
      elevated: 'var(--surface-elevated)',
      soft: 'var(--surface-soft)'
    },
    text: {
      primary: 'var(--text-primary)',
      muted: 'var(--text-muted)'
    },
    border: {
      subtle: 'var(--border-subtle)'
    },
    accent: {
      primary: 'var(--accent-primary)',
      soft: 'var(--accent-soft)'
    },
    severity: {
      high: {
        fg: 'var(--severity-high-fg)',
        pillFg: 'var(--severity-high-pill-fg)',
        pillBg: 'var(--severity-high-pill-bg)'
      }
    }
  },
  typography: {
    display: 'var(--font-display)',
    body: 'var(--font-body)',
    mono: 'var(--font-mono)'
  },
  radius: {
    sm: 'var(--radius-sm)',
    md: 'var(--radius-md)',
    lg: 'var(--radius-lg)'
  },
  spacing: {
    1: 'var(--space-1)',
    2: 'var(--space-2)',
    3: 'var(--space-3)',
    4: 'var(--space-4)',
    6: 'var(--space-6)',
    8: 'var(--space-8)',
    12: 'var(--space-12)',
    16: 'var(--space-16)'
  },
  motion: {
    fast: 'var(--motion-fast)',
    base: 'var(--motion-base)',
    slow: 'var(--motion-slow)'
  },
  layout: {
    shellMaxWidth: 'var(--shell-max-width)'
  },
  shadow: {
    elevated: 'var(--shadow-elevated)'
  }
} as const;
