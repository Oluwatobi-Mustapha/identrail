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

function trimOptional(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function badRequest(res: { status: (code: number) => { json: (payload: unknown) => void } }, message: string) {
  res.status(400).json({ error: message });
}

export default async function handler(
  req: { method?: string; body?: unknown },
  res: { status: (code: number) => { json: (payload: unknown) => void } }
) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const body: LeadCapturePayload = req.body && typeof req.body === 'object' ? (req.body as LeadCapturePayload) : {};
  const email = trimOptional(body.email) ?? '';
  const environment = trimOptional(body.environment) ?? '';

  if (!email || !isValidEmail(email)) {
    badRequest(res, 'Valid work email is required.');
    return;
  }

  if (!environment) {
    badRequest(res, 'Environment is required.');
    return;
  }

  const deploymentModel = trimOptional(body.deployment_model);
  const urgency = trimOptional(body.urgency);
  const teamSize = trimOptional(body.team_size);

  const payload = {
    email,
    environment,
    company: trimOptional(body.company),
    challenge: trimOptional(body.challenge),
    deployment_model: deploymentModel && ALLOWED_DEPLOYMENT_MODELS.has(deploymentModel) ? deploymentModel : undefined,
    scan_goal: trimOptional(body.scan_goal),
    urgency: urgency && ALLOWED_URGENCY.has(urgency) ? urgency : undefined,
    team_size: teamSize && ALLOWED_TEAM_SIZE.has(teamSize) ? teamSize : undefined,
    source: trimOptional(body.source) || 'unknown',
    page_path: trimOptional(body.page_path) || '/',
    captured_at: new Date().toISOString()
  };

  const webhook = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.LEAD_WEBHOOK_URL?.trim();

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
