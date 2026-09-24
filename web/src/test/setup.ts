import '@testing-library/jest-dom/vitest';

if (typeof globalThis.ResizeObserver === 'undefined') {
  class ResizeObserverStub {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  }
  globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
}

if (typeof globalThis.IntersectionObserver === 'undefined') {
  class IntersectionObserverStub {
    readonly root = null;
    readonly rootMargin = '';
    readonly thresholds: number[] = [];

    constructor(private readonly callback: IntersectionObserverCallback) {}

    disconnect(): void {}
    observe(target: Element): void {
      queueMicrotask(() => {
        const rect = target.getBoundingClientRect();
        this.callback(
          [
            {
              boundingClientRect: rect,
              intersectionRatio: 1,
              intersectionRect: rect,
              isIntersecting: true,
              rootBounds: null,
              target,
              time: 0
            }
          ],
          this as unknown as IntersectionObserver
        );
      });
    }
    takeRecords(): IntersectionObserverEntry[] {
      return [];
    }
    unobserve(_target: Element): void {}
  }

  globalThis.IntersectionObserver = IntersectionObserverStub as unknown as typeof IntersectionObserver;
}
