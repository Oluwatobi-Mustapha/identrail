import type { HTMLAttributes } from 'react';
import { cn } from './utils';

export function Separator({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div role="separator" aria-orientation="horizontal" className={cn('ui-separator', className)} {...props} />;
}
