import { customerLogos, whoWeHelpCards } from '../siteContent';

export function WhoWeHelpSection() {
  return (
    <section className="section" aria-labelledby="who-we-help-title">
      <div className="section-header centered">
        <h2 id="who-we-help-title">Who Identrail Helps</h2>
      </div>

      <div className="card-grid who-help-grid">
        {whoWeHelpCards.map((item) => (
          <article key={item.title} className="content-card who-help-card">
            <h3>{item.title}</h3>
            <p>{item.body}</p>
          </article>
        ))}
      </div>

      <div className="logo-strip" aria-label="Customer logos">
        {customerLogos.map((logo) => (
          <span key={logo}>{logo}</span>
        ))}
      </div>
    </section>
  );
}
