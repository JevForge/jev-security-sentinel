import type { EnrichmentMaps } from '../collectors/enrichment.js';
import { applyEnrichment } from '../collectors/enrichment.js';
import type {
  EnvironmentName,
  Exploitability,
  GateEffect,
  GateMode,
  GateScope,
  Severity,
} from '../schemas/enums.js';
import type { AllowlistEntry, Finding, GatePolicy } from '../schemas/sentinel.js';
import type { RawFinding } from '../collectors/common.js';
import { fingerprint } from '../utils/fingerprint.js';
import { matchGlob, matchesAnyGlob } from '../utils/glob.js';

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  unknown: 2,
  info: 1,
};

function effectForSeverity(
  severity: Severity,
  policy: GatePolicy,
  environment: EnvironmentName,
): GateEffect {
  const rules = policy.environments[environment];
  if (rules.block.includes(severity)) return 'blocking';
  if (rules.review.includes(severity)) return 'review';
  if (rules.warn.includes(severity)) return 'warning';
  return 'informational';
}

function escalate(
  effect: GateEffect,
  exploitability: Exploitability,
  severity: Severity,
  policy: GatePolicy,
): GateEffect {
  if (policy.escalate_known_exploited && exploitability === 'known_exploited') {
    if (SEVERITY_RANK[severity] >= SEVERITY_RANK.medium || severity === 'unknown') return 'blocking';
    return effect === 'informational' ? 'review' : effect;
  }
  if (policy.escalate_poc && exploitability === 'poc') {
    if (SEVERITY_RANK[severity] >= SEVERITY_RANK.high) return 'blocking';
    if (SEVERITY_RANK[severity] >= SEVERITY_RANK.medium) return effect === 'blocking' ? effect : 'review';
  }
  return effect;
}

export function pathInChange(filePath: string | null, changed: string[] | null): boolean {
  if (!changed) return true;
  if (!filePath) return true;
  const norm = filePath.replace(/\\/g, '/');
  return changed.some(candidate => {
    const item = candidate.replace(/\\/g, '/').replace(/^\.\//, '');
    return norm === item || norm.endsWith(`/${item}`) || item.endsWith(`/${norm}`);
  });
}

export function isAllowlistExpired(expiresAt: string, now = new Date()): boolean {
  const end = Date.parse(`${expiresAt}T23:59:59.999Z`);
  if (Number.isNaN(end)) return true;
  return now.getTime() > end;
}

function entryMatches(
  entry: AllowlistEntry,
  raw: RawFinding,
  id: string,
  baseFingerprint: string,
): boolean {
  if (entry.rule_id && entry.rule_id === raw.rule_id) return true;
  if (entry.id && entry.id === id) return true;
  if (entry.fingerprint && entry.fingerprint === baseFingerprint) return true;
  if (entry.cve && raw.cve && entry.cve.toUpperCase() === raw.cve.toUpperCase()) return true;
  if (entry.path && raw.path && matchGlob(entry.path, raw.path)) return true;
  return false;
}

function resolveAllowlist(input: {
  raw: RawFinding;
  id: string;
  baseFingerprint: string;
  policy: GatePolicy;
  now: Date;
}): {
  allowlisted: boolean;
  unaudited: boolean;
  expired: boolean;
  owner: string | null;
  reason: string | null;
  expiresAt: string | null;
} {
  for (const entry of input.policy.allowlist.entries) {
    if (!entryMatches(entry, input.raw, input.id, input.baseFingerprint)) continue;
    if (isAllowlistExpired(entry.expires_at, input.now)) {
      return {
        allowlisted: false,
        unaudited: false,
        expired: true,
        owner: entry.owner,
        reason: entry.reason,
        expiresAt: entry.expires_at,
      };
    }
    return {
      allowlisted: true,
      unaudited: false,
      expired: false,
      owner: entry.owner,
      reason: entry.reason,
      expiresAt: entry.expires_at,
    };
  }

  const legacy =
    input.raw.scanner_suppressed ||
    input.policy.allowlist.rule_ids.includes(input.raw.rule_id) ||
    input.policy.allowlist.ids.includes(input.id) ||
    input.policy.allowlist.fingerprints.includes(input.baseFingerprint) ||
    (input.raw.cve
      ? input.policy.allowlist.cves.some(cve => cve.toUpperCase() === input.raw.cve?.toUpperCase())
      : false) ||
    matchesAnyGlob(input.policy.allowlist.paths, input.raw.path);

  if (legacy) {
    return {
      allowlisted: true,
      unaudited: !input.raw.scanner_suppressed,
      expired: false,
      owner: null,
      reason: input.raw.scanner_suppressed ? 'scanner_suppressed' : null,
      expiresAt: null,
    };
  }

  return {
    allowlisted: false,
    unaudited: false,
    expired: false,
    owner: null,
    reason: null,
    expiresAt: null,
  };
}

export function annotateFindings(input: {
  raw: RawFinding[];
  policy: GatePolicy;
  environment: EnvironmentName;
  component: string;
  gateScope: GateScope;
  gateMode?: GateMode;
  baselineFingerprints?: Set<string>;
  changedPaths: string[] | null;
  enrichment?: EnrichmentMaps;
  now?: Date;
}): Finding[] {
  const gateMode = input.gateMode ?? 'all';
  const baseline = input.baselineFingerprints ?? new Set<string>();
  const enrichment = input.enrichment ?? { kev: new Set<string>(), epss: new Map<string, number>() };
  const now = input.now ?? new Date();
  const seen = new Map<string, number>();
  return input.raw.map(raw => {
    const enriched = applyEnrichment(raw.cve, raw.exploitability, enrichment);
    const exploitability = (
      raw.category === 'secrets' && enriched.exploitability === 'unknown' ? 'likely' : enriched.exploitability
    ) as Exploitability;
    const baseId = fingerprint([
      raw.source,
      raw.rule_id,
      raw.path,
      raw.start_line,
      raw.cve,
      raw.title,
    ]);
    const count = seen.get(baseId) ?? 0;
    seen.set(baseId, count + 1);
    const id = `${raw.source}:${count === 0 ? baseId : `${baseId}:${count}`}`;
    const excluded = matchesAnyGlob(input.policy.exclude_paths, raw.path);
    const allow = resolveAllowlist({
      raw,
      id,
      baseFingerprint: baseId,
      policy: input.policy,
      now,
    });
    const inChange = pathInChange(raw.path, input.changedPaths);
    const outOfScope = excluded || (input.gateScope === 'changed' && !inChange);
    const baselineMatched = gateMode === 'new_only' && baseline.has(baseId);
    let gateEffect: GateEffect = 'informational';
    if (allow.allowlisted) gateEffect = 'allowlisted';
    else if (baselineMatched) gateEffect = 'baseline';
    else if (outOfScope) gateEffect = 'out_of_scope';
    else if (raw.category === 'secrets' && input.policy.block_secrets) gateEffect = 'blocking';
    else {
      gateEffect = escalate(
        effectForSeverity(raw.severity, input.policy, input.environment),
        exploitability,
        raw.severity,
        input.policy,
      );
    }
    return {
      id,
      fingerprint: baseId,
      source: raw.source,
      category: raw.category,
      severity: raw.severity,
      title: raw.title,
      rule_id: raw.rule_id,
      path: raw.path,
      start_line: raw.start_line,
      component: raw.component || input.component,
      environment: input.environment,
      cve: raw.cve,
      exploitability,
      in_change: inChange,
      allowlisted: allow.allowlisted,
      allowlist_owner: allow.owner,
      allowlist_reason: allow.reason,
      allowlist_expires_at: allow.expiresAt,
      allowlist_expired: allow.expired,
      epss: enriched.epss,
      kev: enriched.kev,
      excluded,
      baseline_matched: baselineMatched,
      gate_effect: gateEffect,
      message: raw.message,
    };
  });
}
