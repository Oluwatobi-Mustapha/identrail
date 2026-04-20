const outcomes = [
  {
    metric: '87%',
    title: 'Machine identity risk reduced',
    body: 'Prioritized trust-path exposures with actionable remediation and faster closure cycles.'
  },
  {
    metric: '42 hrs/wk',
    title: 'Saved on policy reviews',
    body: 'Simulation-driven approvals removed repetitive manual review loops for platform teams.'
  },
  {
    metric: '14',
    title: 'High-severity NHI exposures blocked',
    body: 'Runtime anomaly detection caught dormant service-account abuse before escalation.'
  },
  {
    metric: '35%',
    title: 'Lower secret-rotation overhead',
    body: 'Automated hygiene and exposure scanning reduced emergency key rotation workflows.'
  }
] as const;

export function OutcomeSection() {
  return (
    <section className="mk-section" aria-labelledby="mk-impact-title">
      <div className="mk-shell">
        <div className="mk-section-head">
          <p className="mk-eyebrow">Identrail Impact in Production</p>
          <h2 id="mk-impact-title">One platform. Measurable machine identity outcomes.</h2>
        </div>

        <div className="mk-impact-grid">
          {outcomes.map((item) => (
            <article key={item.title} className="mk-impact-card">
              <strong>{item.metric}</strong>
              <h3>{item.title}</h3>
              <p>{item.body}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
