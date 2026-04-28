import { afterEach, describe, expect, it, vi } from 'vitest';
import handler from './leads';

type MockResponse = {
  statusCode: number;
  body: unknown;
  status: (code: number) => { json: (payload: unknown) => void };
};

function createMockResponse(): MockResponse {
  return {
    statusCode: 200,
    body: null,
    status(code: number) {
      this.statusCode = code;
      return {
        json: (payload: unknown) => {
          this.body = payload;
        }
      };
    }
  };
}

describe('web/api/leads handler', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.LEAD_WEBHOOK_URL;
  });

  it('rejects invalid email payloads', async () => {
    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'invalid-email',
          environment: 'AWS IAM'
        }
      },
      res
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Valid work email is required.' });
  });

  it('returns 503 when lead webhook is not configured', async () => {
    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes',
          deployment_model: 'Hosted SaaS',
          urgency: 'This quarter',
          team_size: '6-20',
          scan_goal: 'AWS IAM + Kubernetes trust-path risk reduction',
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(503);
    expect(res.body).toEqual({ error: 'Lead capture is not configured.' });
  });

  it('accepts payloads when webhook forwarding succeeds', async () => {
    process.env.LEAD_WEBHOOK_URL = 'https://example.test/webhook';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    const res = createMockResponse();
    await handler(
      {
        method: 'POST',
        body: {
          email: 'security@company.com',
          environment: 'AWS IAM + Kubernetes',
          deployment_model: 'Hosted SaaS',
          urgency: 'This quarter',
          team_size: '6-20',
          scan_goal: 'AWS IAM + Kubernetes trust-path risk reduction',
          source: 'Read-Only Scan Intake',
          page_path: '/read-only-scan'
        }
      },
      res
    );

    expect(res.statusCode).toBe(202);
    expect(res.body).toEqual({ status: 'accepted' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
