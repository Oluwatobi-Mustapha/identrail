import { describe, expect, it, vi } from 'vitest';
import { captureAnalyticsEvent } from './events';

describe('captureAnalyticsEvent', () => {
  it('forwards events to gtag and posthog when available', () => {
    const gtag = vi.fn();
    const capture = vi.fn();

    (window as Window & { gtag?: typeof gtag }).gtag = gtag;
    (window as Window & { posthog?: { capture: typeof capture } }).posthog = { capture };

    captureAnalyticsEvent('cta_click', { placement: 'header' });

    expect(gtag).toHaveBeenCalledWith('event', 'cta_click', { placement: 'header' });
    expect(capture).toHaveBeenCalledWith('cta_click', { placement: 'header' });
  });

  it('still forwards to posthog when gtag throws', () => {
    const gtag = vi.fn(() => {
      throw new Error('blocked');
    });
    const capture = vi.fn();

    (window as Window & { gtag?: typeof gtag }).gtag = gtag;
    (window as Window & { posthog?: { capture: typeof capture } }).posthog = { capture };

    expect(() => captureAnalyticsEvent('cta_click', { placement: 'header' })).not.toThrow();
    expect(gtag).toHaveBeenCalledTimes(1);
    expect(capture).toHaveBeenCalledWith('cta_click', { placement: 'header' });
  });
});
