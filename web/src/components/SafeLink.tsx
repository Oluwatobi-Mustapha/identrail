import type { AnchorHTMLAttributes } from 'react';

type SafeLinkProps = AnchorHTMLAttributes<HTMLAnchorElement> & {
  href: string;
};

function mergeRel(existingRel?: string): string {
  const required = new Set(['noopener', 'noreferrer']);
  if (existingRel) {
    for (const token of existingRel.split(/\s+/)) {
      if (token) required.add(token);
    }
  }
  return Array.from(required).join(' ');
}

function isExternalHTTPLink(href: string): boolean {
  const normalized = href.trim().toLowerCase();
  return (
    normalized.startsWith('http://') ||
    normalized.startsWith('https://') ||
    normalized.startsWith('//')
  );
}

export function SafeLink({ href, target, rel, ...props }: SafeLinkProps) {
  const finalTarget = target ?? (isExternalHTTPLink(href) ? '_blank' : undefined);
  const finalRel = finalTarget === '_blank' ? mergeRel(rel) : rel;

  return <a href={href} target={finalTarget} rel={finalRel} {...props} />;
}
