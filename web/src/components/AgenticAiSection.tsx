import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const controls = [
  'Map AI agent identities, tool tokens, and delegated trust paths',
  'Detect privilege escalation routes from agent to infrastructure',
  'Apply policy guardrails before agent authorization changes reach production'
];

export function AgenticAiSection() {
  return (
    <section className="section" aria-labelledby="agentic-title">
      <div className="agentic-section">
        <div>
          <p className="eyebrow">Built for Modern Workloads</p>
          <h2 id="agentic-title">Identrail for Agentic AI Security</h2>
          <p>
            Bring governance and least-privilege controls to AI agent identities across model
            providers, orchestration layers, and runtime infrastructure.
          </p>
          <SafeLink className="btn btn-primary" href={siteLinks.agenticAi}>
            Explore Agentic AI Security
          </SafeLink>
        </div>
        <ul>
          {controls.map((control) => (
            <li key={control}>{control}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}
