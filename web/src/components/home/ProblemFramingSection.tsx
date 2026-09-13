const identitySignals = [
  {
    name: 'AWS IAM',
    detail: 'role assumptions and policy edges',
    icon: '/brand-logos/aws.svg'
  },
  {
    name: 'Kubernetes',
    detail: 'service accounts, RBAC, namespaces',
    icon: '/brand-logos/kubernetes.svg'
  },
  {
    name: 'GitHub/OIDC',
    detail: 'workflow identity and token claims',
    icon: '/brand-logos/github.svg'
  }
];

export function ProblemFramingSection() {
  return (
    <section className="idt-section idt-problem-frame" aria-labelledby="problem-frame-title">
      <div className="idt-problem-frame-grid">
        <div className="idt-problem-copy">
          <h2 id="problem-frame-title">Connect identity signals. Reveal the path.</h2>
        </div>

        <div className="idt-problem-path-visual" role="group" aria-label="Identity signals converge into the Identrail trust graph">
          <div className="idt-problem-source-stack" aria-label="Source systems">
            {identitySignals.map((signal) => (
              <article className="idt-problem-source-card" key={signal.name}>
                <span className="idt-problem-source-icon">
                  <img src={signal.icon} alt="" aria-hidden="true" loading="lazy" />
                </span>
                <span>{signal.name}</span>
                <small>{signal.detail}</small>
              </article>
            ))}
          </div>

          <div className="idt-problem-path-spine" aria-hidden="true">
            <span />
          </div>

          <div className="idt-problem-map-core">
            <p>Risk graph output</p>
            <strong>From signal to owner-ready fix</strong>
            <div aria-label="Trust graph outputs">
              <span>Evidence</span>
              <span>Reachable impact</span>
              <span>Recommended fix</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
