import { readFileSync, existsSync } from 'node:fs';
import { resolveInsideWorkspace } from '../utils/workspace-path.js';
import { asArray, asRecord, text } from './common.js';

/**
 * Load baseline fingerprints from a workspace JSON file.
 * Accepted shapes:
 * - string[]
 * - { fingerprints: string[] }
 * - { findings: Array<{ fingerprint?: string }> }
 */
export function loadBaselineFingerprints(
  workspace: string,
  relativePath: string,
): { fingerprints: Set<string>; error?: string } {
  const full = resolveInsideWorkspace(workspace, relativePath);
  if (!full) {
    return { fingerprints: new Set(), error: 'Baseline path escapes the workspace' };
  }
  if (!existsSync(full)) {
    return { fingerprints: new Set(), error: `Baseline file not found: ${relativePath}` };
  }
  try {
    const raw = JSON.parse(readFileSync(full, 'utf8')) as unknown;
    const fingerprints = new Set<string>();
    if (Array.isArray(raw)) {
      for (const item of raw) {
        if (typeof item === 'string' && item.length >= 8) fingerprints.add(item);
        else {
          const record = asRecord(item);
          const fp = text(record?.fingerprint);
          if (fp.length >= 8) fingerprints.add(fp);
        }
      }
    } else {
      const record = asRecord(raw);
      for (const item of asArray(record?.fingerprints)) {
        if (typeof item === 'string' && item.length >= 8) fingerprints.add(item);
      }
      for (const item of asArray(record?.findings)) {
        const finding = asRecord(item);
        const fp = text(finding?.fingerprint);
        if (fp.length >= 8) fingerprints.add(fp);
      }
    }
    return { fingerprints };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { fingerprints: new Set(), error: message.slice(0, 180) };
  }
}
