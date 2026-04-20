import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { prerender } from '../src/prerender';
import { PRERENDER_ROUTES } from '../prerender-routes';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '..');
const distDir = path.join(webRoot, 'dist');
const templatePath = path.join(distDir, 'index.html');
const rootMarker = '<div id="root"></div>';

function outputDirForRoute(route: string): string {
  if (route === '/') {
    return distDir;
  }

  return path.join(distDir, route.replace(/^\//, ''));
}

async function main() {
  const template = await readFile(templatePath, 'utf8');

  if (!template.includes(rootMarker)) {
    throw new Error(`Could not find ${rootMarker} in ${templatePath}`);
  }

  for (const route of PRERENDER_ROUTES) {
    const rendered = await prerender({ url: route });
    const html = template.replace(rootMarker, `<div id="root">${rendered.html}</div>`);
    const outputDir = outputDirForRoute(route);

    await mkdir(outputDir, { recursive: true });
    await writeFile(path.join(outputDir, 'index.html'), html, 'utf8');
  }

  console.log(`Prerendered ${PRERENDER_ROUTES.length} routes.`);
}

await main();
