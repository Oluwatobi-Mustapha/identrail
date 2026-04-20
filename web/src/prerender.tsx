import { renderToString } from 'react-dom/server';
import { StaticRouter } from 'react-router-dom';
import { RoutedSite } from './App';

type PrerenderInput = {
  url: string;
};

export async function prerender(data: PrerenderInput) {
  const html = renderToString(
    <StaticRouter location={data.url}>
      <RoutedSite />
    </StaticRouter>
  );

  return { html };
}
