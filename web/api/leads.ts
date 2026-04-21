type LeadCapturePayload = {
  email?: string;
  environment?: string;
  company?: string;
  challenge?: string;
  deployment_model?: string;
  scan_goal?: string;
  urgency?: string;
  team_size?: string;
  source?: string;
  page_path?: string;
};

const ALLOWED_DEPLOYMENT_MODELS = new Set(['Hosted SaaS', 'Self-hosted open-core', 'Enterprise private tenancy']);
const ALLOWED_URGENCY = new Set(['This quarter', 'This month', 'Immediate']);
const ALLOWED_TEAM_SIZE = new Set(['1-5', '6-20', '21-50', '50+']);

function trimOptional(value?: string): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

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
    company: trimOptional(body.company),
    challenge: trimOptional(body.challenge),
    deployment_model: ALLOWED_DEPLOYMENT_MODELS.has(body.deployment_model ?? '')
      ? body.deployment_model
      : trimOptional(body.deployment_model),
    scan_goal: trimOptional(body.scan_goal),
    urgency: ALLOWED_URGENCY.has(body.urgency ?? '') ? body.urgency : trimOptional(body.urgency),
    team_size: ALLOWED_TEAM_SIZE.has(body.team_size ?? '') ? body.team_size : trimOptional(body.team_size),
    source: trimOptional(body.source) || 'unknown',
    page_path: trimOptional(body.page_path) || '/',
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
