import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

export function ReportSection() {
  return (
    <section className="section report-section" aria-labelledby="report-title">
      <div className="section-card report-layout">
        <div>
          <h2 id="report-title">2026 State of Machine Identity Report</h2>
          <p>
            Machine identity risk is spreading across cloud, Kubernetes, and software delivery
            pipelines. Overprivileged service accounts, dormant trust paths, and leaked credentials
            continue to grow faster than manual security workflows can keep up with.
          </p>
          <p>
            This report breaks down the most common machine identity failure patterns and gives
            security teams a practical roadmap for least-privilege enforcement.
          </p>
          <SafeLink className="btn btn-primary" href={siteLinks.reportDownload}>
            Download the Report
          </SafeLink>
        </div>

        <blockquote>
          <p>
            “Security leaders that win in 2026 are the ones that can explain machine identity
            trust, not just human access.”
          </p>
          <footer>
            <strong>Cloud Security Advisor</strong>
            <span>Former enterprise CISO</span>
          </footer>
        </blockquote>
      </div>
    </section>
  );
}
