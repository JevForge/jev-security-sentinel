import { readFileSync, statSync } from 'node:fs';
import { SourceParseError, type RawFinding } from './common.js';
import {
  parseCodeScanning,
  parseDependabot,
  parseNormalized,
  parseSarif,
  parseSecretScanning,
  parseSemgrep,
  parseSnyk,
  parseTrivy,
  parseVeracode,
  parseOsv,
  parseGrype,
  parseCheckov,
} from './parsers.js';
import { resolveReportPathInput } from '../utils/report-paths.js';
import { resolveInsideWorkspace } from '../utils/workspace-path.js';
import type { SourceError } from '../schemas/sentinel.js';

const MAX_BYTES = 20_000_000;

export interface LoadRequest {
  workspace: string;
  normalizedJson?: string;
  /** Single path, comma/newline list, or glob(s). */
  normalizedPath?: string;
  sarifPath?: string;
  semgrepPath?: string;
  trivyPath?: string;
  snykPath?: string;
  veracodePath?: string;
  osvPath?: string;
  grypePath?: string;
  checkovPath?: string;
  maxFindings: number;
  remote?: {
    semgrep?: unknown;
    snyk?: unknown;
    veracode?: unknown;
    codeScanning?: unknown;
    secretScanning?: unknown;
    dependabot?: unknown;
  };
}

export interface LoadResult {
  findings: RawFinding[];
  errors: SourceError[];
  truncated: boolean;
  /** Workspace-relative report files that were successfully opened. */
  loadedPaths: string[];
}

function readJson(workspace: string, userPath: string, source: string, errors: SourceError[]): unknown | undefined {
  const full = resolveInsideWorkspace(workspace, userPath);
  if (!full) {
    errors.push({ source, message: 'Path escapes the workspace' });
    return undefined;
  }
  try {
    const size = statSync(full).size;
    if (size > MAX_BYTES) {
      errors.push({ source, message: 'Report exceeds 20MB' });
      return undefined;
    }
    return JSON.parse(readFileSync(full, 'utf8')) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errors.push({ source, message: message.slice(0, 180) });
    return undefined;
  }
}

function take(
  source: string,
  parser: (data: unknown) => RawFinding[],
  data: unknown,
  bucket: RawFinding[],
  errors: SourceError[],
): void {
  try {
    bucket.push(...parser(data));
  } catch (error) {
    const message = error instanceof SourceParseError || error instanceof Error ? error.message : String(error);
    errors.push({ source, message: message.slice(0, 180) });
  }
}

function loadPathGroup(
  workspace: string,
  raw: string | undefined,
  source: string,
  parser: (data: unknown) => RawFinding[],
  bucket: RawFinding[],
  errors: SourceError[],
  loadedPaths: string[],
): void {
  if (!raw?.trim()) return;
  const resolved = resolveReportPathInput(workspace, raw);
  for (const message of resolved.errors) {
    errors.push({ source, message });
  }
  if (resolved.paths.length === 0 && resolved.errors.length === 0) {
    errors.push({ source, message: `No files matched: ${raw.trim().slice(0, 120)}` });
    return;
  }
  for (const path of resolved.paths) {
    const data = readJson(workspace, path, source, errors);
    if (data === undefined) continue;
    take(source, parser, data, bucket, errors);
    loadedPaths.push(path);
  }
}

export function loadFindings(request: LoadRequest): LoadResult {
  const errors: SourceError[] = [];
  const bucket: RawFinding[] = [];
  const loadedPaths: string[] = [];

  if (request.normalizedJson?.trim()) {
    try {
      take('normalized', parseNormalized, JSON.parse(request.normalizedJson) as unknown, bucket, errors);
    } catch {
      errors.push({ source: 'normalized', message: 'findings JSON input is not valid JSON' });
    }
  }

  loadPathGroup(
    request.workspace,
    request.normalizedPath,
    'normalized',
    parseNormalized,
    bucket,
    errors,
    loadedPaths,
  );
  loadPathGroup(request.workspace, request.sarifPath, 'sarif', parseSarif, bucket, errors, loadedPaths);
  loadPathGroup(request.workspace, request.semgrepPath, 'semgrep', parseSemgrep, bucket, errors, loadedPaths);
  loadPathGroup(request.workspace, request.trivyPath, 'trivy', parseTrivy, bucket, errors, loadedPaths);
  loadPathGroup(request.workspace, request.snykPath, 'snyk', parseSnyk, bucket, errors, loadedPaths);
  loadPathGroup(request.workspace, request.veracodePath, 'veracode', parseVeracode, bucket, errors, loadedPaths);
  loadPathGroup(request.workspace, request.osvPath, 'osv', parseOsv, bucket, errors, loadedPaths);
  loadPathGroup(request.workspace, request.grypePath, 'grype', parseGrype, bucket, errors, loadedPaths);
  loadPathGroup(request.workspace, request.checkovPath, 'checkov', parseCheckov, bucket, errors, loadedPaths);

  const remote = request.remote;
  if (remote?.semgrep !== undefined) take('semgrep', parseSemgrep, remote.semgrep, bucket, errors);
  if (remote?.snyk !== undefined) take('snyk', parseSnyk, remote.snyk, bucket, errors);
  if (remote?.veracode !== undefined) take('veracode', parseVeracode, remote.veracode, bucket, errors);
  if (remote?.codeScanning !== undefined) {
    take('github-code-scanning', parseCodeScanning, remote.codeScanning, bucket, errors);
  }
  if (remote?.secretScanning !== undefined) {
    take('github-secret-scanning', parseSecretScanning, remote.secretScanning, bucket, errors);
  }
  if (remote?.dependabot !== undefined) {
    take('github-dependabot', parseDependabot, remote.dependabot, bucket, errors);
  }

  const truncated = bucket.length > request.maxFindings;
  return {
    findings: truncated ? bucket.slice(0, request.maxFindings) : bucket,
    errors,
    truncated,
    loadedPaths,
  };
}
