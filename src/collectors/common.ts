import type { Category, Exploitability, FindingSource, Severity } from '../schemas/enums.js';
import { sanitizeText, normalizeRepoPath } from '../utils/sanitize.js';

export interface RawFinding {
  source: FindingSource;
  category: Category;
  severity: Severity;
  title: string;
  rule_id: string;
  path: string | null;
  start_line: number | null;
  cve: string | null;
  exploitability: Exploitability;
  message: string;
  component: string;
  scanner_suppressed: boolean;
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function text(value: unknown, max = 300): string {
  if (typeof value === 'string') return sanitizeText(value, max);
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return '';
}

export function lineNumber(value: unknown): number | null {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(n) || n <= 0 || n > 1_000_000) return null;
  return n;
}

export function normalizeSeverity(value: unknown): Severity {
  const raw = text(value, 32).toLowerCase();
  if (raw === 'critical' || raw === '5') return 'critical';
  if (raw === 'high' || raw === 'error' || raw === '4') return 'high';
  if (raw === 'medium' || raw === 'warning' || raw === 'moderate' || raw === '3') return 'medium';
  if (raw === 'low' || raw === 'note' || raw === '2') return 'low';
  if (raw === 'info' || raw === 'informational' || raw === 'none' || raw === '1' || raw === '0') {
    return 'info';
  }
  return 'unknown';
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

export function inferCategory(hints: string[], fallback: Category): Category {
  const blob = hints.join(' ').toLowerCase();
  if (/secret|credential|private-key|password|token/.test(blob)) return 'secrets';
  if (/license/.test(blob)) return 'license';
  if (/container|docker image|os-pkgs/.test(blob)) return 'container';
  if (/iac|terraform|kubernetes|dockerfile|misconfig|cloudformation/.test(blob)) return 'iac';
  if (/cve-\d|dependency|sca|vuln|package/.test(blob)) return 'sca';
  if (/sast|injection|xss|codeql|semgrep/.test(blob)) return 'sast';
  return fallback;
}

export function inferExploitability(hints: string[]): Exploitability {
  const first = hints[0]?.trim().toLowerCase();
  if (
    first === 'known_exploited' ||
    first === 'poc' ||
    first === 'likely' ||
    first === 'unlikely' ||
    first === 'unknown'
  ) {
    return first;
  }
  const blob = hints.join(' ').toLowerCase();
  if (/known.?exploited|cisa.?kev|\bkev\b/.test(blob)) return 'known_exploited';
  if (/proof of concept|\bpoc\b|exploit available|exploit maturity/.test(blob)) return 'poc';
  if (/unlikely|not exploitable|no exploit/.test(blob)) return 'unlikely';
  if (/likely exploitable/.test(blob)) return 'likely';
  return 'unknown';
}

export function cveFrom(hints: string[]): string | null {
  const blob = hints.join(' ');
  const match = blob.match(/CVE-\d{4}-\d{4,7}/i);
  return match ? match[0].toUpperCase() : null;
}

export function makeRaw(input: {
  source: FindingSource;
  category: Category;
  severity: Severity;
  title: string;
  ruleId: string;
  path?: unknown;
  startLine?: unknown;
  cve?: string | null;
  exploitability?: Exploitability;
  message?: string;
  component?: string;
  hints?: string[];
  scannerSuppressed?: boolean;
  hideMessage?: boolean;
}): RawFinding {
  const hints = input.hints ?? [];
  const title = sanitizeText(input.title || input.ruleId || 'Untitled finding', 300) || 'Untitled finding';
  const rule = sanitizeText(input.ruleId || 'unknown', 256) || 'unknown';
  return {
    source: input.source,
    category: input.category,
    severity: input.severity,
    title,
    rule_id: rule,
    path: normalizeRepoPath(input.path),
    start_line: lineNumber(input.startLine),
    cve: input.cve ?? cveFrom([title, rule, ...hints]),
    exploitability: input.exploitability ?? inferExploitability([title, ...hints]),
    message: input.hideMessage ? '' : sanitizeText(input.message ?? '', 500),
    component: sanitizeText(input.component ?? '', 128),
    scanner_suppressed: Boolean(input.scannerSuppressed),
  };
}

export class SourceParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SourceParseError';
  }
}
