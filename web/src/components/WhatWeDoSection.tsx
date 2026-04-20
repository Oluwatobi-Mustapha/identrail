import { whatWeDoCards } from '../siteContent';

export function WhatWeDoSection() {
  return (
    <section className="section" aria-labelledby="what-we-do-title">
      <div className="section-header centered">
        <h2 id="what-we-do-title">What We Do</h2>
      </div>
      <div className="card-grid three-up">
        {whatWeDoCards.map((item) => (
          <article key={item.title} className="content-card">
            <h3>{item.title}</h3>
            <p>{item.body}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
