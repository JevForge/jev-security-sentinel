import { readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { matchGlob } from './glob.js';
import { resolveInsideWorkspace } from './workspace-path.js';

const GLOB_CHARS = /[*?]/;

/** Split Action path inputs on commas or newlines. */
export function splitPathInput(raw: string | undefined | null): string[] {
  if (!raw?.trim()) return [];
  return raw
    .split(/[\n,]+/)
    .map(part => part.trim())
    .filter(Boolean);
}

function hasGlob(pattern: string): boolean {
  return GLOB_CHARS.test(pattern);
}

function walkFiles(root: string, dir: string, out: string[]): void {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      walkFiles(root, full, out);
    } else if (entry.isFile()) {
      out.push(relative(root, full).split(sep).join('/'));
    }
  }
}

function listWorkspaceFiles(workspace: string): string[] {
  const files: string[] = [];
  walkFiles(workspace, workspace, files);
  return files;
}

/**
 * Expand literal paths and globs into workspace-relative paths.
 * Literal paths that escape the workspace are reported as errors.
 * Globs that match nothing are not errors (caller may warn).
 */
export function expandReportPaths(
  workspace: string,
  patterns: string[],
): { paths: string[]; errors: string[] } {
  const errors: string[] = [];
  const seen = new Set<string>();
  const paths: string[] = [];
  let workspaceFiles: string[] | null = null;

  for (const pattern of patterns) {
    const normalized = pattern.replace(/\\/g, '/');
    if (hasGlob(normalized)) {
      if (!workspaceFiles) workspaceFiles = listWorkspaceFiles(workspace);
      for (const file of workspaceFiles) {
        if (!matchGlob(normalized, file)) continue;
        if (seen.has(file)) continue;
        const full = resolveInsideWorkspace(workspace, file);
        if (!full) continue;
        seen.add(file);
        paths.push(file);
      }
      continue;
    }

    const full = resolveInsideWorkspace(workspace, normalized);
    if (!full) {
      errors.push(`Path escapes the workspace: ${normalized}`);
      continue;
    }
    try {
      const st = statSync(full);
      if (!st.isFile()) {
        errors.push(`Not a file: ${normalized}`);
        continue;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`${normalized}: ${message.slice(0, 120)}`);
      continue;
    }
    if (!seen.has(normalized)) {
      seen.add(normalized);
      paths.push(normalized);
    }
  }

  return { paths, errors };
}

/** Parse an Action path input into expanded workspace-relative file paths. */
export function resolveReportPathInput(
  workspace: string,
  raw: string | undefined | null,
): { paths: string[]; errors: string[] } {
  return expandReportPaths(workspace, splitPathInput(raw));
}
