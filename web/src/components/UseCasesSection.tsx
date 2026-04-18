import { useCases } from '../siteContent';
import { SafeLink } from './SafeLink';

export function UseCasesSection() {
  return (
    <section className="section use-cases-section" id="use-cases" aria-labelledby="use-cases-title">
      <div className="section-header">
        <h2 id="use-cases-title">Top Use Cases</h2>
      </div>

      <div className="use-case-grid">
        {useCases.map((item) => (
          <article key={item.id} className="use-case-card">
            <p className="use-case-number">{item.id}</p>
            <h3>{item.title}</h3>
            <p>{item.body}</p>
            <SafeLink href={item.href}>Learn more</SafeLink>
          </article>
        ))}
      </div>
    </section>
  );
}
