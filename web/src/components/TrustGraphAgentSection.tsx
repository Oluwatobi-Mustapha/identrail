import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const beforePolicy = `{
  "Effect": "Allow",
  "Action": ["sts:AssumeRole", "s3:*"],
  "Resource": "*"
}`;

const afterPolicy = `{
  "Effect": "Allow",
  "Action": ["sts:AssumeRole", "s3:GetObject"],
  "Resource": [
    "arn:aws:s3:::prod-artifacts/*"
  ]
}`;

export function TrustGraphAgentSection() {
  return (
    <section className="section reveal-on-scroll" aria-labelledby="agent-title">
      <div className="section-card agent-section">
        <div className="agent-copy">
          <p className="eyebrow eyebrow-dark">Auto-Remediate</p>
          <h2 id="agent-title">Meet the Identrail Trust Graph Agent</h2>
          <p>
            Auto-remediate machine identity risks with one click. The agent analyzes trust paths,
            drafts least-privilege changes, and opens a simulated pull request with policy diffs.
          </p>
          <div className="agent-steps" aria-hidden="true">
            <span>Analyze graph</span>
            <span>Generate fix</span>
            <span>Open PR</span>
          </div>
          <SafeLink className="btn btn-primary" href={siteLinks.agentRelease}>
            Star the repo to get the agent in your next release
          </SafeLink>
        </div>

        <div className="agent-pr-preview" aria-label="Agent remediation pull request preview">
          <div className="agent-icon" aria-hidden="true">
            <span className="agent-eye" />
            <span className="agent-eye" />
          </div>
          <div className="agent-snippet-grid">
            <article>
              <p>Before</p>
              <pre>
                <code>{beforePolicy}</code>
              </pre>
            </article>
            <article>
              <p>After</p>
              <pre>
                <code>{afterPolicy}</code>
              </pre>
            </article>
          </div>
        </div>
      </div>
    </section>
  );
}
