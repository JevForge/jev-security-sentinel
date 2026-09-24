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
} from './parsers.js';
import { resolveInsideWorkspace } from '../utils/workspace-path.js';
import type { SourceError } from '../schemas/sentinel.js';

const MAX_BYTES = 20_000_000;

export interface LoadRequest {
  workspace: string;
  normalizedJson?: string;
  normalizedPath?: string;
  sarifPath?: string;
  semgrepPath?: string;
  trivyPath?: string;
  snykPath?: string;
  veracodePath?: string;
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

export function loadFindings(request: LoadRequest): LoadResult {
  const errors: SourceError[] = [];
  const bucket: RawFinding[] = [];

  if (request.normalizedJson?.trim()) {
    try {
      take('normalized', parseNormalized, JSON.parse(request.normalizedJson) as unknown, bucket, errors);
    } catch {
      errors.push({ source: 'normalized', message: 'findings JSON input is not valid JSON' });
    }
  }
  if (request.normalizedPath) {
    const data = readJson(request.workspace, request.normalizedPath, 'normalized', errors);
    if (data !== undefined) take('normalized', parseNormalized, data, bucket, errors);
  }
  if (request.sarifPath) {
    const data = readJson(request.workspace, request.sarifPath, 'sarif', errors);
    if (data !== undefined) take('sarif', parseSarif, data, bucket, errors);
  }
  if (request.semgrepPath) {
    const data = readJson(request.workspace, request.semgrepPath, 'semgrep', errors);
    if (data !== undefined) take('semgrep', parseSemgrep, data, bucket, errors);
  }
  if (request.trivyPath) {
    const data = readJson(request.workspace, request.trivyPath, 'trivy', errors);
    if (data !== undefined) take('trivy', parseTrivy, data, bucket, errors);
  }
  if (request.snykPath) {
    const data = readJson(request.workspace, request.snykPath, 'snyk', errors);
    if (data !== undefined) take('snyk', parseSnyk, data, bucket, errors);
  }
  if (request.veracodePath) {
    const data = readJson(request.workspace, request.veracodePath, 'veracode', errors);
    if (data !== undefined) take('veracode', parseVeracode, data, bucket, errors);
  }

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
  };
}
