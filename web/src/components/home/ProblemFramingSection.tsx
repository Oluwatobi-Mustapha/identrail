export function ProblemFramingSection() {
  return (
    <section className="idt-section idt-shell idt-problem-frame" aria-labelledby="problem-frame-title">
      <div className="idt-problem-frame-grid">
        <div>
          <p className="idt-eyebrow">Why teams miss machine identity risk</p>
          <h2 id="problem-frame-title">Trust data is fragmented across cloud, cluster, and CI systems.</h2>
          <p>
            IAM policies, Kubernetes RBAC, and OIDC workflow identities are usually reviewed in separate tools. Attack paths are not.
            That gap is where overprivileged machine access survives into production.
          </p>
        </div>

        <div className="idt-problem-signals" role="list" aria-label="Fragmentation signals">
          <article role="listitem">
            <h3>AWS IAM in one console</h3>
            <p>Role assumptions and cross-account trust are reviewed without Kubernetes or CI context.</p>
          </article>
          <article role="listitem">
            <h3>Kubernetes RBAC in another</h3>
            <p>Service account privilege drift is visible, but downstream cloud reachability remains opaque.</p>
          </article>
          <article role="listitem">
            <h3>CI/OIDC evidence in logs</h3>
            <p>Workflow identity misuse is discovered late because chain-level visibility is missing during review.</p>
          </article>
        </div>
      </div>
    </section>
  );
}
