import { IntegrationsCtaSection } from './components/IntegrationsCtaSection';
import { MarketingFooter } from './components/MarketingFooter';
import { MarketingHeader } from './components/MarketingHeader';
import { MarketingHero } from './components/MarketingHero';
import { OutcomeSection } from './components/OutcomeSection';
import { PlatformStorySection } from './components/PlatformStorySection';
import { ProofSection } from './components/ProofSection';
import { TechnicalShowcaseSection } from './components/TechnicalShowcaseSection';

export function App() {
  return (
    <div className="mk-site">
      <a className="mk-skip" href="#main-content">
        Skip to content
      </a>

      <MarketingHeader />

      <main id="main-content">
        <MarketingHero />
        <OutcomeSection />
        <PlatformStorySection />
        <TechnicalShowcaseSection />
        <ProofSection />
        <IntegrationsCtaSection />
      </main>

      <MarketingFooter />
    </div>
  );
}
