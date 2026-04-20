import { impactCards } from '../siteContent';

export function ImpactSection() {
  return (
    <section className="section" aria-labelledby="impact-title">
      <div className="section-header centered">
        <h2 id="impact-title">Identrail Impact</h2>
      </div>

      <div className="impact-grid">
        {impactCards.map((item) => (
          <article key={item.title} className="impact-card">
            <h3>{item.title}</h3>
            <p>{item.body}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
