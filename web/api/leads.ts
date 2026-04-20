type LeadCapturePayload = {
  email?: string;
  environment?: string;
  company?: string;
  challenge?: string;
  source?: string;
  page_path?: string;
};

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function badRequest(res: { status: (code: number) => { json: (payload: unknown) => void } }, message: string) {
  res.status(400).json({ error: message });
}

export default async function handler(
  req: { method?: string; body?: LeadCapturePayload },
  res: { status: (code: number) => { json: (payload: unknown) => void } }
) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const body = req.body ?? {};
  const email = (body.email ?? '').trim();
  const environment = (body.environment ?? '').trim();

  if (!email || !isValidEmail(email)) {
    badRequest(res, 'Valid work email is required.');
    return;
  }

  if (!environment) {
    badRequest(res, 'Environment is required.');
    return;
  }

  const payload = {
    email,
    environment,
    company: body.company?.trim() || undefined,
    challenge: body.challenge?.trim() || undefined,
    source: body.source?.trim() || 'unknown',
    page_path: body.page_path?.trim() || '/',
    captured_at: new Date().toISOString()
  };

  const webhook = process.env.LEAD_WEBHOOK_URL?.trim();

  if (webhook) {
    try {
      const forward = await fetch(webhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!forward.ok) {
        res.status(502).json({ error: 'Lead forwarding failed.' });
        return;
      }
    } catch {
      res.status(502).json({ error: 'Lead forwarding failed.' });
      return;
    }
  }

  res.status(202).json({ status: 'accepted' });
}
