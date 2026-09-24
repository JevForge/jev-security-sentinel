import { createHash } from 'node:crypto';

export function fingerprint(parts: Array<string | number | null | undefined>): string {
  const raw = parts.map(part => String(part ?? '')).join('|');
  return createHash('sha256').update(raw).digest('hex').slice(0, 16);
}
