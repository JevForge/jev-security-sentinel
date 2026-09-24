import { isAbsolute, relative, resolve } from 'node:path';

export function resolveInsideWorkspace(workspace: string, userPath: string): string | null {
  const root = resolve(workspace);
  const full = resolve(root, userPath);
  const rel = relative(root, full);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) return null;
  return full;
}
