type EventProperties = Record<string, unknown>;

export function captureAnalyticsEvent(eventName: string, properties: EventProperties = {}): void {
  if (typeof window === 'undefined') {
    return;
  }

  const globalWindow = window as Window & {
    gtag?: (...args: unknown[]) => void;
    posthog?: {
      capture: (event: string, properties?: EventProperties) => void;
    };
  };

  if (globalWindow.gtag) {
    try {
      globalWindow.gtag('event', eventName, properties);
    } catch {
      // Never block the caller due to analytics transport failures.
    }
  }

  if (globalWindow.posthog) {
    try {
      globalWindow.posthog.capture(eventName, properties);
    } catch {
      // Never block the caller due to analytics transport failures.
    }
  }
}
