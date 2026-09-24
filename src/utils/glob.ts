export function matchGlob(pattern: string, value: string): boolean {
  const normalized = value.replace(/\\/g, '/');
  const source = pattern
    .replace(/\\/g, '/')
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '::DS::')
    .replace(/\*/g, '[^/]*')
    .replace(/::DS::/g, '.*');
  return new RegExp(`^${source}$`).test(normalized);
}

export function matchesAnyGlob(patterns: string[], value: string | null | undefined): boolean {
  if (!value || patterns.length === 0) return false;
  return patterns.some(pattern => matchGlob(pattern, value));
}
