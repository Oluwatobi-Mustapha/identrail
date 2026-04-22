const WORKFLOW_STEPS = [
  {
    title: '1. Discover trust relationships',
    description: 'Collect AWS IAM, Kubernetes, GitHub, and OIDC identity metadata in read-only mode.',
    output: 'Output: identity graph snapshot with source evidence links'
  },
  {
    title: '2. Prioritize reachable risk paths',
    description: 'Score findings by severity, privilege depth, and production blast-radius potential.',
    output: 'Output: ranked findings queue with owner-ready context'
  },
  {
    title: '3. Simulate policy hardening',
    description: 'Preview trust-policy changes and estimate affected workloads before enforcement.',
    output: 'Output: remediation plan with expected impact summary'
  },
  {
    title: '4. Roll out with safety controls',
    description: 'Deploy in stages with rollback options and track resolution outcomes.',
    output: 'Output: audit-ready remediation timeline and status history'
  }
] as const;

export function HowItWorksSection() {
  return (
    <section className="idt-section idt-shell" aria-labelledby="workflow-title">
      <div className="idt-section-title">
        <p className="idt-eyebrow">Operational Workflow</p>
        <h2 id="workflow-title">From read-only discovery to safe enforcement</h2>
        <p>Each stage produces a concrete artifact security and platform teams can review before taking action.</p>
      </div>

      <ol className="idt-steps idt-workflow-track">
        {WORKFLOW_STEPS.map((step) => (
          <li key={step.title}>
            <h3>{step.title}</h3>
            <p>{step.description}</p>
            <p className="idt-workflow-output">{step.output}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
